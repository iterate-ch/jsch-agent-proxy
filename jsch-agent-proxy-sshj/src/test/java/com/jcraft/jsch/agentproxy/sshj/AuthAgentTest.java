package com.jcraft.jsch.agentproxy.sshj;

import com.jcraft.jsch.agentproxy.AgentProxy;
import net.schmizz.sshj.common.KeyType;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AuthAgentTest {

    @Test
    public void testSignFlagsRsa() {
        assertEquals(0, AuthAgent.getSignFlags(KeyType.RSA, "ssh-rsa"));
        assertEquals(AgentProxy.SSH_AGENT_RSA_SHA2_256, AuthAgent.getSignFlags(KeyType.RSA, "rsa-sha2-256"));
        assertEquals(AgentProxy.SSH_AGENT_RSA_SHA2_512, AuthAgent.getSignFlags(KeyType.RSA, "rsa-sha2-512"));
    }

    @Test
    public void testSignFlagsRsaCertificate() {
        assertEquals(0, AuthAgent.getSignFlags(KeyType.RSA_CERT, "ssh-rsa-cert-v01@openssh.com"));
        assertEquals(AgentProxy.SSH_AGENT_RSA_SHA2_256, AuthAgent.getSignFlags(KeyType.RSA_CERT, "rsa-sha2-256-cert-v01@openssh.com"));
        assertEquals(AgentProxy.SSH_AGENT_RSA_SHA2_512, AuthAgent.getSignFlags(KeyType.RSA_CERT, "rsa-sha2-512-cert-v01@openssh.com"));
    }

    @Test
    public void testSignFlagsOtherKeyTypes() {
        assertEquals(0, AuthAgent.getSignFlags(KeyType.ED25519, "ssh-ed25519"));
        assertEquals(0, AuthAgent.getSignFlags(KeyType.ED25519_CERT, "ssh-ed25519-cert-v01@openssh.com"));
        assertEquals(0, AuthAgent.getSignFlags(KeyType.ECDSA256, "ecdsa-sha2-nistp256"));
        assertEquals(0, AuthAgent.getSignFlags(KeyType.DSA, "ssh-dss"));
        // flags are only meaningful for RSA keys, whatever the algorithm name says
        assertEquals(0, AuthAgent.getSignFlags(KeyType.ED25519, "rsa-sha2-256"));
        assertEquals(0, AuthAgent.getSignFlags(KeyType.UNKNOWN, "rsa-sha2-512-cert-v01@openssh.com"));
    }
}
