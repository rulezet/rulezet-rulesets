rule Win_Trojan_VPK_2
{
strings:
	$a0 = { ba8000b90100b80103cd138bf5eb8e578085f40033c64508fe83c71db000b91100f3aa5feb }


condition:
	$a0
}