/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2013 Olli Helenius All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.jcraft.jsch.agentproxy.sshj;

import com.hierynomus.sshj.key.KeyAlgorithm;
import com.hierynomus.sshj.key.KeyAlgorithms;
import com.jcraft.jsch.agentproxy.AgentProxy;
import com.jcraft.jsch.agentproxy.Identity;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.method.AbstractAuthMethod;

import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;

/**
 * An AuthMethod for sshj authentication with an agent.
 */
public class AuthAgent extends AbstractAuthMethod {

    /**
     * The AgentProxy instance that is used for signing
     */
    private final AgentProxy agentProxy;
    /**
     * The identity from Agent
     */
    private final Identity identity;
    /**
     * The identity's key algorithm
     */
    private final String algorithm;
    private final String comment;

    private Queue<KeyAlgorithm> available;

    private final KeyType keyType;

    public AuthAgent(AgentProxy agentProxy, Identity identity) throws Buffer.BufferException {
        super("publickey");
        this.agentProxy = agentProxy;
        this.identity = identity;
        this.comment = new String(identity.getComment());
        this.algorithm = (new Buffer.PlainBuffer(identity.getBlob())).readString();
        this.keyType = KeyType.fromString(algorithm);
    }

    private KeyAlgorithm getPublicKeyAlgorithm(KeyType keyType) throws TransportException {
        if (available == null) {
            available = new LinkedList<>(params.getTransport().getClientKeyAlgorithms(keyType));
        }
        return available.peek();
    }

    @Override
    public boolean shouldRetry() {
        if (available != null) {
            available.poll();
            return !available.isEmpty();
        }
        return false;
    }

    protected SSHPacket putPubKey(SSHPacket reqBuf)
            throws UserAuthException {
        try {
            KeyAlgorithm ka = getPublicKeyAlgorithm(keyType);
            if (ka != null) {
                reqBuf.putString(ka.getKeyAlgorithm()).putBytes(identity.getBlob()).getCompactData();
                return reqBuf;
            }
        } catch (IOException ioe) {
            throw new UserAuthException("No KeyAlgorithm configured for key " + keyType, ioe);
        }
        throw new UserAuthException("No KeyAlgorithm configured for key " + keyType);
    }

    private int getSignFlags(KeyAlgorithm algorithm) {
        if (keyType == KeyType.RSA) {
            if (KeyAlgorithms.RSASHA256().getName().equals(algorithm.getKeyAlgorithm())) {
                return AgentProxy.SSH_AGENT_RSA_SHA2_256;
            }
            if (KeyAlgorithms.RSASHA512().getName().equals(algorithm.getKeyAlgorithm())) {
                return AgentProxy.SSH_AGENT_RSA_SHA2_512;
            }
        }
        return 0;
    }

    protected SSHPacket putSig(SSHPacket reqBuf)
            throws TransportException {
        final byte[] dataToSign = new Buffer.PlainBuffer()
                .putString(params.getTransport().getSessionID())
                .putBuffer(reqBuf) // & rest of the data for sig
                .getCompactData();

        reqBuf.putBytes(agentProxy.sign(identity.getBlob(), dataToSign, getSignFlags(getPublicKeyAlgorithm(keyType))));

        return reqBuf;
    }

    /**
     * Internal use.
     */
    @Override
    public void handle(Message cmd, SSHPacket buf)
            throws UserAuthException, TransportException {
        if (cmd == Message.USERAUTH_60)
            sendSignedReq();
        else
            super.handle(cmd, buf);
    }

    /**
     * Builds SSH_MSG_USERAUTH_REQUEST packet.
     *
     * @param signed whether the request packet will contain signature
     * @return the {@link SSHPacket} containing the request packet
     * @throws UserAuthException
     */
    private SSHPacket buildReq(boolean signed)
            throws UserAuthException {
        log.debug("Attempting authentication using agent identity {}", comment);
        return putPubKey(super.buildReq().putBoolean(signed));
    }

    /**
     * Send SSH_MSG_USERAUTH_REQUEST containing the signature.
     *
     * @throws UserAuthException
     * @throws TransportException
     */
    private void sendSignedReq()
            throws UserAuthException, TransportException {
        log.debug("Key acceptable, sending signed request");
        params.getTransport().write(putSig(buildReq(true)));
    }

    /**
     * Builds a feeler request (sans signature).
     */
    @Override
    protected SSHPacket buildReq()
            throws UserAuthException {
        return buildReq(false);
    }
}
