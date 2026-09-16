rule HKTL_CN_Project1 {
	meta:
		description = "Chinese Hacktool Set - file Project1.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "Project1"
		hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		id = "12cc7a82-d7a9-58c6-b283-3bb0df477cd8"
	strings:
		$s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
		$s2 = "Password.txt" fullword ascii
		$s3 = "LoginPrompt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}