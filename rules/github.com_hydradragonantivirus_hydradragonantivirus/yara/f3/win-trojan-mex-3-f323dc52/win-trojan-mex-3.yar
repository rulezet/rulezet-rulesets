rule Win_Trojan_Mex_3
{
strings:
	$a0 = { 558bec81ecdc0900005668a01040006a006a00ff15541040008985b0f6ffff83bdb0f6ffff00740d }


condition:
	$a0
}