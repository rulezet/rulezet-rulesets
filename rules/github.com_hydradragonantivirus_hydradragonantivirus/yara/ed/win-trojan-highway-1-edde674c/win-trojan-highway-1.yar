rule Win_Trojan_Highway_1
{
strings:
	$a0 = { 5c484947485741592e444c4c005eacaa0ac075fa6a0068800000006a026a006a }


condition:
	$a0
}