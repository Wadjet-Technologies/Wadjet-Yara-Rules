import "hash"

rule VSCode_Malicious_Extensions_Malkolm {
        meta:
            description = "Detects malicious VS Code theme remake extensions published by Malkolm"
            author = "Wadjet Technologies LLC"
            date = "2026-10-14"
            reference = "https://www.reversinglabs.com/blog/malicious-vs-code-fake-image"
            threat_type = "Supply Chain Attack / Malicious Extension"
            severity = "Critical"

    strings:
        // Core extension package identifiers found inside package.json or extension paths
        $ext_1 = "malkolm.theme-artschool-remake" ascii wide nocase
        $ext_2 = "malkolm.theme-ascetic-remake" ascii wide nocase
        $ext_3 = "malkolm.theme-aurora-remake" ascii wide nocase
        $ext_4 = "malkolm.theme-azure-remake" ascii wide nocase
        $ext_5 = "malkolm.theme-bashling-remake" ascii wide nocase

     condition:
        // Match if any of the extension identifier strings are present
        any of ($ext_*) or 
        
        // Match on the specific SHA-1 hashes of the malicious files/VSIX artifacts
        hash.sha1(0, filesize) == "edcbdb65d8653c11be197bd188241813bf431bc7" or // theme-artschool-remake
        hash.sha1(0, filesize) == "c6e5b9c41e5dd7cadc7247bcfbaeb643ade61e46" or // theme-ascetic-remake
        hash.sha1(0, filesize) == "71c241a7110abb70bff59d22e0238bc5553d495a" or // theme-aurora-remake
        hash.sha1(0, filesize) == "9985d8e1c820cf4bdf25f7b0023d2b879c8af722" or // theme-azure-remake
        hash.sha1(0, filesize) == "7cb116b08bda294d962b28bf47ece4b40d9ed2a8"    // theme-bashling-remake
}





rule VSCode_Malicious_Extensions_PandaExpress {
    meta:
        description = "Detects specific malicious PandaExpress theme plugins by SHA-1 hash"
        author = "Wadjet Technologies LLC"
        date = "2026-10-14"
        reference = "https://www.reversinglabs.com/blog/malicious-vs-code-fake-image"
     
      strings:
        // Core extension package identifiers found inside package.json or extension paths
        $ext_1 = "pandaexpress.theme-anarchist-plugin" ascii wide nocase
        $ext_2 = "pandaexpress.theme-anarchisteighties-plugin" ascii wide nocase
        $ext_3 = "pandaexpress.theme-ant-plugin" ascii wide nocase
        $ext_4 = "pandaexpress.theme-array-plugin" ascii wide nocase
        $ext_5 = "pandaexpress.theme-arstotzka-plugin" ascii wide nocase
     
     
     condition:
        
        // Match if any of the extension identifier strings are present
        any of ($ext_*) or 
        
        // Match on the specific SHA-1 hashes of the malicious files/VSIX artifacts
        hash.sha1(0, filesize) == "77c76d6d067821bc3a34b734a719df44a39c12df" or
        hash.sha1(0, filesize) == "451dc570125d4e0db47217d5e177d0fa94c8bbb3" or
        hash.sha1(0, filesize) == "578b6b117d433b71e3cb69c2062ab61f29171ae6" or
        hash.sha1(0, filesize) == "dc40c33ffbca097917f17f7482eef295856d8076" or
        hash.sha1(0, filesize) == "6a1fc337ec7fdfaa89604d686cf5afef5057dc90"
}





