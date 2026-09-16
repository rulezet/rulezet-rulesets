rule Win_Trojan_Timebomb_4
{
strings:
	$a0 = { ebd8b43ecd21be0303bf7a048bdf8bcf2bcefcf3a4b90100ba8000b80103cd13ba060272b5 }


condition:
	$a0
}