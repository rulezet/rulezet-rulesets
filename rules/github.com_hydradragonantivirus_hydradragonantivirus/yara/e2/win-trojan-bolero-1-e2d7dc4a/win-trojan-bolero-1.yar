rule Win_Trojan_Bolero_1
{
strings:
	$a0 = { b89fba429941b099b53c060346a143f7f87353b56ec187b29e6becb8ebe81a919608ab46bd5db00e }


condition:
	$a0
}