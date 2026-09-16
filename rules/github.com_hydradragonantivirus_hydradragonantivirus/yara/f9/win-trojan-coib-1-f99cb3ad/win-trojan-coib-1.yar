rule Win_Trojan_Coib_1
{
strings:
	$a0 = { fc3e750981fbc7077503939dcf3d004b7503e853009dea }


condition:
	$a0
}