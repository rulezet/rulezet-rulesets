rule Win_Trojan_N_30
{
strings:
	$a0 = { 46ee44b107ec4df750468694a30bd82d76c595e0a294a40b7285d82dec4a698184c3cb94a3f7d82d }


condition:
	$a0
}