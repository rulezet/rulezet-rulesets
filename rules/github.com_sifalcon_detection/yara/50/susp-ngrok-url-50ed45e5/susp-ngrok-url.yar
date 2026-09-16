rule SUSP_Ngrok_URL : pe download {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects a PE file that contains an ngrok.io URL. This can be used as C2 channel"

	strings:
		$url = "ngrok.io" nocase wide

	condition:
		uint16(0) == 0x5a4d 
		and $url
}