rule Win_Trojan_Phantom1_2
{
strings:
	$a0 = { 770536f519911da1799536a3c903893408f77100969b42e412 }


condition:
	$a0
}