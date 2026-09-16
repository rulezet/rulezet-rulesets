rule Win_Trojan_Peace_3
{
strings:
	$a0 = { 01b90903ba0001b440cd21b80157ba1114cd21e8d2ffba200103d6b441cd21e91500 }


condition:
	$a0
}