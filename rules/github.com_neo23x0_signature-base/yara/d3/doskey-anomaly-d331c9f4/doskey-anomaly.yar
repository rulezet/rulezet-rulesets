rule doskey_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file doskey.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "f2d1995325df0f3ca6e7b11648aa368b7e8f1c7f"
		id = "be9c239a-2918-5330-bbd0-33cc17067f70"
	strings:
		$s3 = "Keyboard History Utility" fullword wide
	condition:
		filename == "doskey.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}