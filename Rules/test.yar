rule ExampleRule
{
    meta:
		version = ""
		date = ""
		modified = ""
		status = "*"
		sharing = "*"
		source = "*"
		author = "*"
		description = "*"
		category = "*"
		info|exploit|technique|tool|malware = "*"
		malware_type = ""
		mitre_att = ""
		actor_type = ""
		actor = ""
		report = ""
		report = ""
		report = ""
		hash = ""
		hash = ""
		hash = ""
		vol_script = ""
    strings:
        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $my_text_string or $my_hex_string
}