package com.netcracker.dummyPage;

import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;


public class server {

    private static final Logger LOGGER = Logger.getLogger(server.class.getName());
    private static Properties config = new Properties();

    public static void main(String[] args) throws Exception {

        // Read configs
        InputStream input = null;

        try {
            input = new FileInputStream("./config.properties");
            config.load(input);
        } catch (IOException ex) {
            LOGGER.log(Level.SEVERE, ex.toString(), ex);
            return;
        } finally {
            if (input != null) input.close();
        }

        // Setup http handlers
        HttpHandler defaultHandler = new HttpHandler() {
            @Override
            public void handle(HttpExchange t) throws IOException {
                String htmlResult = "";

                try (BufferedReader br = new BufferedReader(new FileReader("./index.html"))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        htmlResult += line.replace("%date%", args[0]);
                    }
                }

                t.sendResponseHeaders(404, htmlResult.length());
                OutputStream os = t.getResponseBody();
                os.write(htmlResult.getBytes());
                os.close();
            }
        };

        HttpHandler healthcheckHandler = new HttpHandler() {
            @Override
            public void handle(HttpExchange t) throws IOException {
                String response = config.getProperty("healthcheck.content");

                t.sendResponseHeaders(Integer.parseInt(config.getProperty("healthcheck.httpresp")), response.length());
                OutputStream os = t.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        };

        InetSocketAddress sockHttp = new InetSocketAddress(Integer.parseInt(config.getProperty("server.port")));

        HttpServer server;
        if (Boolean.parseBoolean(config.getProperty("server.https"))) {
            server = HttpsServer.create(sockHttp, 0);
        } else {
            server = HttpServer.create(sockHttp, 0);
        }

        if (Boolean.parseBoolean(config.getProperty("server.https"))) {

            // Init Identity Keystore
            FileInputStream f_ks = new FileInputStream(config.getProperty("server.keystore"));
            KeyStore ks = KeyStore.getInstance(config.getProperty("server.keystore.type"));
            ks.load(f_ks, config.getProperty("server.keystore.pass").toCharArray());

            Certificate pkey = ks.getCertificate(config.getProperty("server.pkey.alias"));
            KeyManagerFactory keyMF = KeyManagerFactory.getInstance("SunX509");
            keyMF.init(ks, config.getProperty("server.pkey.pass").toCharArray());

            // Init Trust Keystore
            FileInputStream f_tks = new FileInputStream(config.getProperty("server.truststore"));
            KeyStore tks = KeyStore.getInstance(config.getProperty("server.truststore.type"));
            tks.load(f_tks, config.getProperty("server.truststore.pass").toCharArray());

            TrustManagerFactory trustMF = TrustManagerFactory.getInstance("SunX509");
            trustMF.init(tks);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyMF.getKeyManagers(), trustMF.getTrustManagers(), null);

            ((HttpsServer) server).setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        SSLEngine sslEngine = sslContext.createSSLEngine();
                        params.setNeedClientAuth(false); // Two-way SSL
                        params.setCipherSuites(sslEngine.getEnabledCipherSuites());
                        params.setProtocols(sslEngine.getEnabledProtocols());

                        SSLParameters defSSLParams = sslContext.getDefaultSSLParameters();
                        params.setSSLParameters(defSSLParams);
                    } catch (Exception ex) {
                        LOGGER.log(Level.SEVERE, ex.toString(), ex);
                        return;
                    }
                }
            });
        }

        server.createContext("/", defaultHandler);
        server.createContext(config.getProperty("healthcheck.uri"), healthcheckHandler);
        server.start();
    }


}
