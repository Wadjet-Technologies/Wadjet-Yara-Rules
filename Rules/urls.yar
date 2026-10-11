rule ambking1234 {
    meta:
        description = "Detects URLs matching ambking1234. Seen in beaconing activity, potential association with ScamGambling or PeckBirdy."
        author = "Charis Grubb"

    strings:
        // Matches http:// or https:// followed by subdomain with ambking1234 domain.
        $bad_url_regex = /https?:\/\/[a-zA-Z0-9\-\.]*ambking1234[a-zA-Z0-9\-\.]*\.(cx|click|dev|cc|com|biz)\/[a-zA-Z0-9_\-\/\?\=\&]+/ nocase


    condition:
        $bad_url_regex
}

