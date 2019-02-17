/*
 * Copyright (c) 2006-2017 DFBnc Developers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.dfbnc.sockets.secure;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

// import com.dfbnc.DFBnc;
import com.dfbnc.sockets.ConnectedSocket;
import com.dfbnc.sockets.SocketWrapper;

/**
 * This defines a Secure (ssl) Socket.
 */
public class SecureSocket extends SocketWrapper {
    /**
     * Create a new SecureSocket
     *
     * @param channel Channel to Wrap.
     * @param owner ConnectedSocket that owns this.
     * @param key The selection key corresponding to the channel's registration
     * @param sslContextManager SSLContextManager to obtain SSLContext from.
     * @throws IOException If there is a problem creating and setting up the socket
     */
    public SecureSocket (final SocketChannel channel, final ConnectedSocket owner, final SelectionKey key, final SSLContextManager sslContextManager) throws IOException {
        super(channel, owner, key);

        try {
            /* SSLEngine used for this socket */
            SSLEngine sslEngine = sslContextManager.getSSLContext().createSSLEngine();
            sslEngine.setUseClientMode(false);
            sslEngine.setWantClientAuth(true);
            sslEngine.beginHandshake();

            myByteChannel = new SSLByteChannel(channel, sslEngine);
            ((SSLByteChannel)myByteChannel).addHandshakeCompletedListener(owner);
        } catch (final Exception e) {
            throw new IOException("Error setting up SSL Socket: "+e.getMessage(), e);
        }
    }

    @Override
    public boolean handleIOException(final IOException ioe) {
        if (ioe instanceof SSLException) {
            if (ioe.getMessage().contains("plaintext connection?")) {
                // Downgrade the socket so that the user sees our error message.
                myByteChannel = null;
            }
            this.sendLine("ERROR :- Closing socket due to SSL Error: " + ioe.getMessage());
        }

        return true;
    }
}
