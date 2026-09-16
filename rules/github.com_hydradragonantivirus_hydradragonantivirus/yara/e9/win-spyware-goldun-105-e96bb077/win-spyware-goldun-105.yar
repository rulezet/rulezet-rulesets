rule Win_Spyware_Goldun_105
{
strings:
	$a0 = { 65722e73796d61561dc01206637200faecdf368048741e2e6d636166656513b03790ff6f776e }


condition:
	$a0
}