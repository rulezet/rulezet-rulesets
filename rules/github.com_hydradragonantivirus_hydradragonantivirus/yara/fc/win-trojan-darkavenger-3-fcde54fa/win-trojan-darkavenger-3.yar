rule Win_Trojan_DarkAvenger_3
{
strings:
	$a0 = { 73482e3b1e0807753a85db7436e8ab029de883007234 }


condition:
	$a0
}