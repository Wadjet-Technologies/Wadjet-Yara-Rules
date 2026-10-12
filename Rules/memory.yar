

rule Cryptomining_Dynamic_Strings {
    meta:
        description="Strings that have been found during dynamic analysis to be related to various cryptomining malware."
    strings:

        //Core indicators
        $minergate = "minergate" nocase
        $monerohash = "monerohash" nocase
        $supernova ="supernova" nocase
        $dwarfpool = "dwarfpool" nocase
        $aeonpool = "aeon.pool" nocase

         // Accompanying Stratum protocol and mining parameters
        $stratum1 = "stratum+tcp://" ascii wide
        $stratum2 = "stratum+ssl://" ascii wide
        $param1 = "--donate-level=" ascii wide
        $param2 = "--userpass" ascii wide
        $param3 = "-o --url" ascii wide

    condition:
        (1 of ($minergate, $supernova, $dwarfpool, $aeonpool, $monerohash)) and  (2 of ($stratum*, $param*))
         
}