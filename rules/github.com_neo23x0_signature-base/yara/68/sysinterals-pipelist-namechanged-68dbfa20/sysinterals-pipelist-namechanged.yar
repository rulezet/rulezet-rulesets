rule SysInterals_PipeList_NameChanged {
	meta:
		description = "Detects NirSoft PipeList"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
		id = "01afcf29-a74c-5be2-8b24-694a2802ef34"
	strings:
		$s1 = "PipeList" ascii fullword
		$s2 = "Sysinternals License" ascii fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 170KB and all of them
		and not filename contains "pipelist.exe"
		and not filename contains "PipeList.exe"
}