rule Win_Trojan_Win_51
{
strings:
	$a0 = { 28000000f7e103f081c6f80000008bfe83ee28b82e58696eabb865320000ab8b4514ab8b461048 }


condition:
	$a0
}