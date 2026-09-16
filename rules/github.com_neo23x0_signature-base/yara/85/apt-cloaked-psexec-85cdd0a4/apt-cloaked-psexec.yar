rule APT_Cloaked_PsExec
	{
	meta:
		description = "Looks like a cloaked PsExec. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		id = "e389bb76-0d1d-5e0e-9f79-a3117c919da3"
	strings:
		$s0 = "psexesvc.exe" wide fullword
		$s1 = "Sysinternals PsExec" wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1
		and not filename matches /(psexec.exe|PSEXESVC.EXE|PsExec64.exe)$/is
		and not filepath matches /RECYCLE.BIN\\S-1/
}