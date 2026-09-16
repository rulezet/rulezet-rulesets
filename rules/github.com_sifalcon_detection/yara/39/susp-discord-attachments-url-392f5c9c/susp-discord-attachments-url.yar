rule SUSP_Discord_Attachments_URL : pe download {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "19.02.2022"
		description = "Detects a PE file that contains an Discord Attachments URL. This is often used by Malware to download further payloads"
		version = "0.1"

	strings:
		$url = "cdn.discordapp.com/attachments" nocase wide

	condition:
		uint16(0) == 0x5a4d 
		and $url
}