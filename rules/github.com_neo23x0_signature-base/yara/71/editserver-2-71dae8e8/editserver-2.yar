rule EditServer_2 {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
		id = "bd254bd9-fd23-5807-9347-2a559089b7c5"
	strings:
		$s0 = "@HOTMAIL.COM"
		$s1 = "Press Any Ke"
		$s3 = "glish MenuZ"
	condition:
		all of them
}