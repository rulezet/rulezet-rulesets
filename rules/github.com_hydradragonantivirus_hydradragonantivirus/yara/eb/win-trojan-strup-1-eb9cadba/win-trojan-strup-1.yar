rule Win_Trojan_Strup_1
{
strings:
	$a0 = { 6e69616c206f6603fe0d0511766963652041747499eaecff5b0c205b4275696c64202331325d3f13c5ff6f8eba1d703a2f2f79 }


condition:
	$a0
}