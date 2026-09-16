rule Win_Trojan_Vienna_23
{
strings:
	$a0 = { 02ebab8a863a03241e3c1e74ee81be3e03bdfb77e68db6 }


condition:
	$a0
}