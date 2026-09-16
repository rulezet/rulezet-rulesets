rule rdrbs100 {
	meta:
		description = "Webshells Auto-generated - file rdrbs100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7c752bcd6da796d80a6830c61a632bff"
		id = "369e5ce0-984c-54eb-96d4-fbfb4f932ba6"
	strings:
		$s3 = "Server address must be IP in A.B.C.D format."
		$s4 = " mapped ports in the list. Currently "
	condition:
		all of them
}