rule Win_Trojan_Jacov_7
{
strings:
	$a0 = { 03cf8db617018bfeb9f200ad7304abe2fac335526b73f7 }


condition:
	$a0
}