package com.packetanalyzer.model;

public enum AppType {

    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    public static AppType fromDomain(String domain) {

        if (domain == null || domain.isBlank()) {
            return UNKNOWN;
        }

        String d = domain.toLowerCase();

        if (d.contains("youtube")
                || d.contains("googlevideo")) {
            return YOUTUBE;
        }

        if (d.contains("google")) {
            return GOOGLE;
        }

        if (d.contains("facebook")
                || d.contains("fbcdn")) {
            return FACEBOOK;
        }

        if (d.contains("twitter")
                || d.contains("x.com")) {
            return TWITTER;
        }

        if (d.contains("instagram")) {
            return INSTAGRAM;
        }

        if (d.contains("netflix")) {
            return NETFLIX;
        }

        if (d.contains("amazon")) {
            return AMAZON;
        }

        if (d.contains("microsoft")) {
            return MICROSOFT;
        }

        if (d.contains("apple")) {
            return APPLE;
        }

        if (d.contains("whatsapp")) {
            return WHATSAPP;
        }

        if (d.contains("telegram")) {
            return TELEGRAM;
        }

        if (d.contains("tiktok")) {
            return TIKTOK;
        }

        if (d.contains("spotify")) {
            return SPOTIFY;
        }

        if (d.contains("zoom")) {
            return ZOOM;
        }

        if (d.contains("discord")) {
            return DISCORD;
        }

        if (d.contains("github")) {
            return GITHUB;
        }

        if (d.contains("cloudflare")) {
            return CLOUDFLARE;
        }

        return HTTPS;
    }
}