rule Win_Trojan_Ermua_1
{
strings:
	$a0 = { 035848508f47036bc040500787064e00508f064d7d }


condition:
	$a0
}