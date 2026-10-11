rule ambking1234 {
    meta:
        description = "Detects URLs matching ambking1234"
        author = "Charis Grubb"

    strings:
        // Matches http:// or https:// followed by suspicious subdomains or TLDs
        $bad_url_regex = /https?:\/\/[a-zA-Z0-9\-\.]*ambking1234[a-zA-Z0-9\-\.]*\.(cx|click|dev|cc|com|biz)\/[a-zA-Z0-9_\-\/\?\=\&]+/ nocase


    condition:
        $bad_url_regex
}

