rule Win_Trojan_PHX_1
{
strings:
	$a0 = { c606f703e92eff06f203b440b9f70333d2e8c2fe32c033c933d2b442e8b7feb440e808018b0e16 }


condition:
	$a0
}