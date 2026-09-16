rule TrojanDownloaderWin32PerkeshSamle
{
	meta:
		Description  = "Trojan.Perkesh.rc"
		ThreatLevel  = "5"
	strings:
		$a = "698d51" ascii wide
		$b = "%s~%x.dat" ascii wide
		$c = "\\drivers\\etc\\hosts" ascii wide
	condition:
		all of them
}