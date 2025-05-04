package org.example;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.Test;

public class OCSPRespReaderTest {
    OCSPRespReader reader = new OCSPRespReader();

    @Test
    public void byteArrayTestValidateAndDecodeGoodResp() throws IOException, OCSPException {
        OCSPResp resp = reader.validateAndParse(goodStatusResp);
        assertNotNull(resp);
        assertEquals(OCSPResp.SUCCESSFUL, resp.getStatus());
        assertNotNull(resp.getResponseObject());
    }

    @Test
    public void base64TestValidateAndDecodeGoodResp() throws IOException, OCSPException {
        OCSPResp resp = reader.validateAndParse(base64GoodStatusResp);
        assertNotNull(resp);
        assertEquals(OCSPResp.SUCCESSFUL, resp.getStatus());
        assertNotNull(resp.getResponseObject());
    }

    @Test
    public void base64MalformedResp() {
        OCSPException e = assertThrows(OCSPException.class, () -> reader.validateAndParse(emptyExtSeq));
        assertThat(e.getMessage(), containsString("Malformed OCSP response:"));
    }

    @Test
    public void invalidResp() {
        IOException e = assertThrows(IOException.class, () -> reader.validateAndParse(invalidResp));
        assertThat(e.getMessage(), containsString("Unexpected error while parsing OCSP response:"));
    }

    @Test
    public void ocspRespFileDoesNotExist() {
        IOException e = assertThrows(IOException.class, () -> reader.readOCSPResponse("/some/unexisting/file"));
        assertThat(e.getMessage(), containsString("OCSP file does not exist or is not readable:"));
    }

    @Test
    public void ocspRespFromFile() throws IOException {
        try {
            Path tempOcspFile = Files.createTempFile("ocsp", ".resp");
            Files.write(tempOcspFile, goodStatusResp);
            String[] args = {tempOcspFile.toAbsolutePath().toString()};
            OCSPRespReader.main(args);
        } catch (IOException e) {
            fail("Expected no exception, but got: " + e.getMessage());
        }
    }

    private static byte[] goodStatusResp = new byte[] {48, -126, 3, -71, 10, 1, 0, -96, -126, 3, -78, 48, -126, 3, -82, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 1, 4, -126, 3, -97, 48, -126, 3, -101, 48, -127, -97, -94, 22, 4, 20, -23, -33, 123, 42, -87, 105, -5, -97, -72, 93, -53, -117, -34, 58, 89, 103, -14, -9, -32, 41, 24, 15, 50, 48, 49, 54, 48, 53, 51, 48, 48, 54, 53, 50, 53, 55, 90, 48, 88, 48, 86, 48, 65, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, -96, 18, -27, 62, -72, -39, 106, -4, -19, -38, 37, 96, 1, 89, 111, 33, -84, -11, -65, 88, 4, 20, -23, -33, 123, 42, -87, 105, -5, -97, -72, 93, -53, -117, -34, 58, 89, 103, -14, -9, -32, 41, 2, 8, 117, -42, 71, 12, 111, 23, -17, -47, -128, 0, 24, 15, 50, 48, 49, 54, 48, 53, 51, 48, 48, 54, 53, 50, 53, 55, 90, -95, 26, 48, 24, 48, 22, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 9, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 5, 5, 0, 3, -127, -127, 0, -127, -30, 102, 85, 109, 67, 84, -73, -37, 126, -94, 107, 125, -81, 117, -123, -53, -97, -26, 122, -126, 14, -26, -107, -121, 60, -109, -85, -59, -22, -96, -96, 39, 76, 119, 105, -50, -23, -56, -51, -66, -64, 25, 110, 50, 67, 89, -111, -77, -50, -75, -81, 120, 51, 60, 25, -126, -91, 43, -75, 94, -77, 32, -76, -22, -68, -29, 39, 70, 11, 48, 32, -107, -63, -49, 11, -68, 52, -64, -7, -123, 107, 13, -100, -111, -73, -102, -9, 8, 45, 51, 84, -105, -2, -75, -16, 42, -32, 107, 99, -71, 16, 63, 110, -92, -94, -77, 35, 71, 41, -18, 92, -81, 51, 124, 73, 75, 29, -24, -53, -87, 88, -22, -121, 115, 33, 87, -1, -96, -126, 2, 98, 48, -126, 2, 94, 48, -126, 2, 90, 48, -126, 1, -61, -96, 3, 2, 1, 2, 2, 8, 117, -42, 71, 12, 111, 23, -17, -47, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 48, 52, 49, 13, 48, 11, 6, 3, 85, 4, 5, 19, 4, 49, 50, 51, 52, 49, 35, 48, 33, 6, 3, 85, 4, 3, 12, 26, 73, 110, 116, 101, 103, 114, 97, 116, 101, 100, 79, 99, 115, 112, 82, 101, 115, 112, 111, 110, 115, 101, 84, 101, 115, 116, 48, 30, 23, 13, 49, 54, 48, 53, 51, 48, 48, 54, 52, 50, 53, 54, 90, 23, 13, 49, 54, 48, 54, 48, 57, 48, 54, 53, 50, 53, 54, 90, 48, 52, 49, 13, 48, 11, 6, 3, 85, 4, 5, 19, 4, 49, 50, 51, 52, 49, 35, 48, 33, 6, 3, 85, 4, 3, 12, 26, 73, 110, 116, 101, 103, 114, 97, 116, 101, 100, 79, 99, 115, 112, 82, 101, 115, 112, 111, 110, 115, 101, 84, 101, 115, 116, 48, -127, -97, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -127, -115, 0, 48, -127, -119, 2, -127, -127, 0, -72, -35, 112, 1, 58, 82, 75, 19, 28, -58, 72, 107, -126, 110, -76, 37, 29, -59, -101, -82, 125, -20, 23, 122, 49, 22, 3, -106, -53, -26, 36, -106, -47, 46, 37, -98, -89, -28, -2, -118, -98, 77, 96, 42, 23, 110, -119, -74, -3, 33, -111, -9, 61, 12, 20, 125, -15, -2, 9, 50, -125, -56, -34, -114, 80, 84, -54, 111, -86, 74, -65, -45, 30, 110, 127, 64, 118, -59, 115, 36, 73, -55, 99, 94, -44, 20, -84, 28, -33, -20, -115, 25, -57, 107, 72, 29, 35, 109, 108, -98, -69, -102, 6, 46, 67, 81, -103, 15, 105, -9, 28, 83, 27, 79, 112, -2, -28, 72, -128, -40, 4, 69, -4, 14, 83, 24, 16, -75, 2, 3, 1, 0, 1, -93, 117, 48, 115, 48, 15, 6, 3, 85, 29, 19, 1, 1, -1, 4, 5, 48, 3, 1, 1, -1, 48, 14, 6, 3, 85, 29, 15, 1, 1, -1, 4, 4, 3, 2, 1, -122, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, -23, -33, 123, 42, -87, 105, -5, -97, -72, 93, -53, -117, -34, 58, 89, 103, -14, -9, -32, 41, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, -128, 20, -23, -33, 123, 42, -87, 105, -5, -97, -72, 93, -53, -117, -34, 58, 89, 103, -14, -9, -32, 41, 48, 16, 6, 3, 85, 29, 32, 4, 9, 48, 7, 48, 5, 6, 3, 41, 1, 1, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 3, -127, -127, 0, 23, 38, -109, 105, 76, -49, 21, -77, -21, -16, -117, -110, 41, -54, -87, -70, -52, 100, 4, 9, 103, -1, 74, 64, -126, -15, -24, 65, -50, 107, -17, -37, -67, -101, 98, -62, 60, 64, -26, 56, 92, 119, 45, -40, 97, -14, -55, -56, -32, -34, 41, 62, 1, 82, 29, -64, 78, -121, 102, 27, -7, 61, 18, 32, 122, 9, -91, -20, 99, 28, 87, 0, -25, -14, -2, 50, -53, 48, 49, 96, -74, -61, 54, -17, 36, -66, -36, -66, 115, -19, 78, -92, 10, -12, -127, -81, -84, -43, -53, 41, -81, -62, 45, -1, -13, -38, 2, 17, 103, 54, -94, 38, -66, -56, -29, -28, -29, -30, 5, 58, 127, -62, 79, -98, -76, -80, 27, -93};
    private static byte[] base64GoodStatusResp = Base64.getDecoder().decode("MIIDuQoBAKCCA7IwggOuBgkrBgEFBQcwAQEEggOfMIIDmzCBn6IWBBTp33sqqWn7n7hdy4veOlln8vfgKRgPMjAxNjA1MzAwNjUyNTdaMFgwVjBBMAkGBSsOAwIaBQAEFKAS5T642Wr87dolYAFZbyGs9b9YBBTp33sqqWn7n7hdy4veOlln8vfgKQIIddZHDG8X79GAABgPMjAxNjA1MzAwNjUyNTdaoRowGDAWBgkrBgEFBQcwAQIECTEyMzQ1Njc4OTANBgkqhkiG9w0BAQUFAAOBgQCB4mZVbUNUt9t+omt9r3WFy5/meoIO5pWHPJOrxeqgoCdMd2nO6cjNvsAZbjJDWZGzzrWveDM8GYKlK7VesyC06rzjJ0YLMCCVwc8LvDTA+YVrDZyRt5r3CC0zVJf+tfAq4GtjuRA/bqSisyNHKe5crzN8SUsd6MupWOqHcyFX/6CCAmIwggJeMIICWjCCAcOgAwIBAgIIddZHDG8X79EwDQYJKoZIhvcNAQELBQAwNDENMAsGA1UEBRMEMTIzNDEjMCEGA1UEAwwaSW50ZWdyYXRlZE9jc3BSZXNwb25zZVRlc3QwHhcNMTYwNTMwMDY0MjU2WhcNMTYwNjA5MDY1MjU2WjA0MQ0wCwYDVQQFEwQxMjM0MSMwIQYDVQQDDBpJbnRlZ3JhdGVkT2NzcFJlc3BvbnNlVGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuN1wATpSSxMcxkhrgm60JR3Fm6597Bd6MRYDlsvmJJbRLiWep+T+ip5NYCoXbom2/SGR9z0MFH3x/gkyg8jejlBUym+qSr/THm5/QHbFcyRJyWNe1BSsHN/sjRnHa0gdI21snruaBi5DUZkPafccUxtPcP7kSIDYBEX8DlMYELUCAwEAAaN1MHMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFOnfeyqpafufuF3Li946WWfy9+ApMB8GA1UdIwQYMBaAFOnfeyqpafufuF3Li946WWfy9+ApMBAGA1UdIAQJMAcwBQYDKQEBMA0GCSqGSIb3DQEBCwUAA4GBABcmk2lMzxWz6/CLkinKqbrMZAQJZ/9KQILx6EHOa+/bvZtiwjxA5jhcdy3YYfLJyODeKT4BUh3ATodmG/k9EiB6CaXsYxxXAOfy/jLLMDFgtsM27yS+3L5z7U6kCvSBr6zVyymvwi3/89oCEWc2oia+yOPk4+IFOn/CT560sBuj");
    private static byte[] emptyExtSeq = Base64.getDecoder().decode("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");
    private static byte[] invalidResp = Base64.getDecoder().decode("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");
}
