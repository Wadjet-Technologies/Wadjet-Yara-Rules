rule ambking1234 {
    meta:
        description = "Detects URLs matching ambking1234. Seen in beaconing activity, potential association with ScamGambling or PeckBirdy."
        author = "Charis Grubb"
        threat_level = "Low"
        last_update = "2026-10-11"

    strings:
        // Matches http:// or https:// followed by subdomain with ambking1234 domain.
        $bad_url_regex = /https?:\/\/[a-zA-Z0-9\-\.]*ambking1234[a-zA-Z0-9\-\.]*\.(cx|click|dev|cc|com|biz)\/[a-zA-Z0-9_\-\/\?\=\&]+/ nocase


    condition:
        $bad_url_regex
}

rule immortales {
    meta:
        description = "Info Stealer Malware from urhaus.abuse.ch"
    strings:
        $url_regex = /https?:\/\/[a-zA-Z0-9\-\.]*immortales.fun\/[a-zA-Z0-9_\-\/\?\=\&]+/ nocase

    condition:
        $url_regex
}

rule fake_claude{
    meta:
        description = "Fake claud ad redirects to fake claude download page designed to trick macOS users into executing malicious commands"

    strings:
        $url1= "claude-desk-code.com"

    condition:
        $url1
}

rule Conti_Ransomeware {
    meta:
        description = "CISA listed domains associated with Conti Ransomware"
        reference = "https://www.bleepingcomputer.com/news/security/cisa-updates-conti-ransomware-alert-with-nearly-100-domain-names/"
    strings:
        $url1 = "badiwaw.com"
        $url2 = "balacif.com"
        $url3 = "barovur.com"
    
    condition:
        any of them
}