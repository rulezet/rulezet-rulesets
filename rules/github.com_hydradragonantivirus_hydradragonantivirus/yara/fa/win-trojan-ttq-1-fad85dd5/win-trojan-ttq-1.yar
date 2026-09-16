rule Win_Trojan_TTQ_1
{
strings:
	$a0 = { cd218ec3582d0300c1e8048cca03c250681a00cb0e1fb8dd4bcd213d4bdd742d8c0642018c0646018c064a01bb }


condition:
	$a0
}