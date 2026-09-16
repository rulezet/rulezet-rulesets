rule Win_Trojan_Bancos_1835
{
strings:
	$a0 = { 9e11190f1ce720845164a48a51ce8faccf9583cb4a0308386ab7bd3813c36b72a067bb16db89003c1ad6681e27cdd207d2ba81d370f9ed3b47623ccf7651d5765eeae661a6c2 }


condition:
	$a0
}