rule Win_Trojan_Torm_3
{
strings:
	$a0 = { 5250b440b967018bd6cd21b8024233c933d2cd21b90002f7f1408994cd008984cf00585ab910 }


condition:
	$a0
}