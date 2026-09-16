rule Win_Trojan_Dementia_1
{
strings:
	$a0 = { 5d81ed12018bf581c638018bdd81c30d018a278a57 }


condition:
	$a0
}