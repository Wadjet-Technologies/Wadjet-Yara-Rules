rule Gaslight
{
    meta:
        description = "Gaslight Malware uses AI triaging system on Mac OS to make the system believe it has been compromised in order to actually compromise the system. " 
    strings:
        $Adhoc_signing_identifier = "endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea"
        $LaunchAgentLabel = "com.apple.system.services.activity"
        $pythonPayLoad = "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239"
        $bash_script_installer = "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"
        $mach_o_sample = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"
        $bonzai_sample = "77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca"
    
    condition:
        $Adhoc_signing_identifier or $LaunchAgentLabel or $pythonPayLoad
}