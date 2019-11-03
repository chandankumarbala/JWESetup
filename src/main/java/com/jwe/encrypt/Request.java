package com.jwe.encrypt;



public class Request {

    private String publickey="-----BEGIN CERTIFICATE-----\n" +
            "MIIDEzCCAfugAwIBAgIJALmOJSdnsfAeMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV\n" +
            "BAMMFWxvY2FsaG9zdC5wYXJ0bmVyLmNvbTAeFw0xOTEwMjExNTE3MTBaFw0yOTEw\n" +
            "MTgxNTE3MTBaMCAxHjAcBgNVBAMMFWxvY2FsaG9zdC5wYXJ0bmVyLmNvbTCCASIw\n" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANGmDVXmN47DnKO1GQGQ1VZ8pkKt\n" +
            "gdbz/iegoesTuoggMPPFd6k1qKQihxQh5JX50+FLMaC+JyDgMMqSO5zqc56h3ZKL\n" +
            "bUbzCzx2NSflU3qIvDu54BFcGVwEWdCEdR+d/gcUnJ4ee+xuqjs9N84M7W3lwE6D\n" +
            "wgTUJOCBj0gdshbIOXzWoP+tHy90oM5RqDKfZSjiYwgxA4nsyu67ULmlTubSuesf\n" +
            "9AEuCh2HCUxg0LkZjou4DxnUx5cKt+4I8kphcP8QPCKhYScyFl/J5ZB6kvMpSgXu\n" +
            "juBc3jkODdKqB8i0QBBnPXAKJJYa3yZb+NaBc/H8Syg4OMg7xfLYjjzlbFECAwEA\n" +
            "AaNQME4wHQYDVR0OBBYEFFsbxpLI9jLX8maZJDQqPmeys9w8MB8GA1UdIwQYMBaA\n" +
            "FFsbxpLI9jLX8maZJDQqPmeys9w8MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF\n" +
            "BQADggEBAGcjU55zqN09e+wr1KEETQpAYWbRgm4JTYvnaWMIGadaa+dhOCyP6oaQ\n" +
            "FVJmZQFKGe67M8O9tVkqE4fs06707iAPzllPU46W/aK4UzS4NtnhjbK6iR6G8niz\n" +
            "PD1/Mi7YOy0RmSr3sgnmlT2U8R/to4LXE6i5/Sxyji0/kf1Y36FkCYTAHD4yxW1A\n" +
            "8LH6a6TNVKKu3RYJJy9tYpUq8M/L6rhv/YEcTCOLu08bDens9TzABC9uj7hkouT3\n" +
            "pZpQ4ncET17sKuR++/B93rPYqLKL5eka1BeLk1ysBfPJZRPq+LPPix13jkhV9JeB\n" +
            "uimr1w1MGGl5wUrdFWLt07JGH31S+R8=\n" +
            "-----END CERTIFICATE-----";

    private String privateKey="-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEA0aYNVeY3jsOco7UZAZDVVnymQq2B1vP+J6Ch6xO6iCAw88V3\n" +
            "qTWopCKHFCHklfnT4UsxoL4nIOAwypI7nOpznqHdkottRvMLPHY1J+VTeoi8O7ng\n" +
            "EVwZXARZ0IR1H53+BxScnh577G6qOz03zgztbeXAToPCBNQk4IGPSB2yFsg5fNag\n" +
            "/60fL3SgzlGoMp9lKOJjCDEDiezK7rtQuaVO5tK56x/0AS4KHYcJTGDQuRmOi7gP\n" +
            "GdTHlwq37gjySmFw/xA8IqFhJzIWX8nlkHqS8ylKBe6O4FzeOQ4N0qoHyLRAEGc9\n" +
            "cAoklhrfJlv41oFz8fxLKDg4yDvF8tiOPOVsUQIDAQABAoIBAQCCyQhAsiGumjE5\n" +
            "n1w+MdAk6BYAOqVpJ0VCC193exM+oHZpXKLNmH/gBPongQ1M0lFvlq0bDgTy6WkG\n" +
            "tjsiJNCEAY5sQTamsDAuQ7/dZ56wLmTfDZHOwpm/Yad2AWvfkXxLhnw9196PHGpu\n" +
            "Ej6h+EaV7GIPmPqMcJugwrJT1tKmipjKCY4qKMsiIocpCYH+GZ3D2M7xrQ6Aff24\n" +
            "a0F9YyfYvVHuoQ13OHq17fMpKsZcIqXvTYtG8WubXDsERlShUHRx/Yt5iwgLBTqw\n" +
            "w2gdCp7CTvlncS/8n79nAIsubbOKcAv9tns6LU7JnVMM/nP+HnUpawY4P2qro6DK\n" +
            "HKL8lzkBAoGBAO4kz1fzr+XdjVegLEiUyGVYKl2kiAvmk3tG6zqVoq9JIJmlD2tl\n" +
            "5aB8U8nFyYadiqrlc6vQ0Sa9xunbcKjgP4ZIUuxlop81ZthOk4u21PijM1LoJxK6\n" +
            "mTh3LGyx0ci96jLgciCPEJF/ubbdXybC8Aa9YZVhALpVPPMBbKwyI19ZAoGBAOFe\n" +
            "RoBZ6k5D95upOF1jz0LBX9CgOO7v8BokIy3BZfM4xrj7e4gUMe8P7S+zsANohQh0\n" +
            "oNffnT9Wf40MgAk/a+SjJASUWqSm/0c/Lzt3TBzsg/SfIMd52M/EowZMJQBZlopv\n" +
            "CLfjJo1O9XQPq/1Nld1DoYzOhSUQcryD/AS/rg25AoGAMh+pTJfL9BPXxhO+fmBi\n" +
            "dYJDGIai4+5aKF5a8G/CWCaKKAyn3DEMTeUdNaDds+nA4At/dzBydTcIgPxhEApz\n" +
            "FG5wlbUmr1/sD6cqQwPue47OJKscXkLMMShUP2SGBTyD6MV5AAVctWMu0aBygJQT\n" +
            "NTfzLB/IqW97bqJkHzJGY7ECgYEAw8Dcog33zAWTZFzm/Y99brGCpTcWXMyClGJB\n" +
            "QDQVdt8hFXozAa7w9IKz9dQxFbTKoN6U+w1bi7F5Vy29ZMr2z4C4/1VRKmV3pQ4H\n" +
            "27IypYj20RsLINkAbu+Q3x5yoUwvy4zIWNlwGhu0bhxSutGSU7+z6hdUZS5VStOl\n" +
            "qwZHi9kCgYAHpI434jHb+znARC1dVoxO/840IvCiwJ8BhRhKeclUR0edM2i89PmK\n" +
            "sw0LAyoOtnlC7Hu0p0vDjDKs7bEqGtnxnFHrR7IxbwpJfZLqOnlOkw+krkBNkK++\n" +
            "v3ugk11IquD/7k9jZZ3chLoVVJ1BR0/FVA2M1vzOc7M7NzO2K225lw==\n" +
            "-----END RSA PRIVATE KEY-----";

    public String getPublickey() {
        return publickey;
    }

    public String getPrivateKey() {
        return privateKey;
    }
}
