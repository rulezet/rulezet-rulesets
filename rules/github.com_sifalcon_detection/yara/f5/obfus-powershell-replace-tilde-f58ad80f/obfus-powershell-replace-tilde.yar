rule OBFUS_PowerShell_Replace_Tilde {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "10.02.2022"
		description = "Detects usage of Replace to replace tilde. Often observed in obfuscation"
		reference = "https://bazaar.abuse.ch/sample/4c391b57d604c695925938bfc10ceb4673edd64e9655759c2aead9e12b3e17cf/"

	strings:
		$a = ".Replace(\"~\",\"0\")"

	condition:
		filesize < 400KB
		and $a
}