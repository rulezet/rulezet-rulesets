rule Win_Trojan_Trivial_430
{
strings:
	$a0 = { 32edb405cd1380fe207404fec6ebee80fd20740632 }


condition:
	$a0
}