

rule Cryptomining_Dynamic_Strings {
    meta:
        description="Strings that have been found during dynamic analysis to be related to various cryptomining malware."
    
    condition:
        "minergate" or "monerohash" or "supernova" or "dwarfpool" or "aeon.pool"
}