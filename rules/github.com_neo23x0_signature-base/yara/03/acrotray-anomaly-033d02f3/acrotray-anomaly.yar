rule Acrotray_Anomaly {
	meta:
		description = "Detects an acrotray.exe that does not contain the usual strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 75
		id = "e3fef644-e535-5137-ac98-2fd1b7ca4361"
	strings:
		$s1 = "PDF/X-3:2002" fullword wide
		$s2 = "AcroTray - Adobe Acrobat Distiller helper application" fullword wide
		$s3 = "MS Sans Serif" fullword wide
		$s4 = "COOLTYPE.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB
		and ( filename == "acrotray.exe" or filename == "AcroTray.exe" )
		and not all of ($s*)
}