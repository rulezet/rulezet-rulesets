rule Win_Trojan_NPox_4
{
strings:
	$a0 = { 741780fc1174ae80fc1274a93dcd7b7503eb06902e }


condition:
	$a0
}