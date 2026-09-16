rule SndVol_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file SndVol.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "e057c90b675a6da19596b0ac458c25d7440b7869"
		id = "0c4d705f-4b24-55f9-bcf4-3f65eea0b7af"
	strings:
		$s1 = "Volume Control Applet" fullword wide
	condition:
		filename == "sndvol.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}