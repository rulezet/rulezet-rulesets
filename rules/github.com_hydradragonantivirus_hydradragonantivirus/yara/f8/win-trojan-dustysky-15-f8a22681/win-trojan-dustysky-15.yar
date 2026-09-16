rule Win_Trojan_DustySky_15
{
strings:
	$a0 = { 3f3f3f3f20464269203f3f3f3f3f20202727203f3f203f3f3f3f203f3f27272e657865 }


condition:
	$a0
}