

rule Cryptomining_Dynamic_Strings {
    meta:
        description="Strings that have been found during dynamic analysis to be related to various cryptomining malware."
    strings:
        $minergate = "minergate" nocase
        $monerohash = "monerohash" nocase
        $supernova ="supernova" nocase
        $dwarfpool = "dwarfpool" nocase
        $aeonpool = "aeon.pool" nocase
    condition:
        any of them
         
}