rule Win_Trojan_A4F_1
{
strings:
	$a0 = { 4d45520d0a008db62100b86201ffd08db62900b86201ffd08db631008dbe3a00b86002ffd08d }


condition:
	$a0
}