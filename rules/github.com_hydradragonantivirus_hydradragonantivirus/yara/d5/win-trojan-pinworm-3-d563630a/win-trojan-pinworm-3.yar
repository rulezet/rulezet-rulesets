rule Win_Trojan_Pinworm_3
{
strings:
	$a0 = { eb135003ea5252e951539e40ad960b03b8ab }


condition:
	$a0
}