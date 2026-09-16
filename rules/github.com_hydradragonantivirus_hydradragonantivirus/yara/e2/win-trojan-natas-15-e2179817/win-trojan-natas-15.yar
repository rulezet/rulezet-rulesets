rule Win_Trojan_Natas_15
{
strings:
	$a0 = { 010090bf4000908edf90836dd306908b45d390b10a90d3c890eb1690b80a029033db90ba0001b9 }


condition:
	$a0
}