rule Win_Trojan_Vundo_39
{
strings:
	$a0 = { 60e88b1800000e7607f0fd662f }


condition:
	$a0
}