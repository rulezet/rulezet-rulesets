rule Win_Trojan_Hippie_2
{
strings:
	$a0 = { fabc007c8ed3fb8edba113044848c1e00650538ec0b80302b90300ba8000cd13cb }


condition:
	$a0
}