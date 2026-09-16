rule Win_Trojan_Jacov_2
{
strings:
	$a0 = { 03cf8db617018bfeb9e500ad7304abe2fac335124173f7 }


condition:
	$a0
}