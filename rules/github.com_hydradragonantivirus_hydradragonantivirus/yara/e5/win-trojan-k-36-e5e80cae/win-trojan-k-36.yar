rule Win_Trojan_K_36
{
strings:
	$a0 = { 012e8a8494032e8c84b10350061e0e0e071fffb49003ffb49203ffb48c03ffb48e03ffb49503ffb497038d94f803 }


condition:
	$a0
}