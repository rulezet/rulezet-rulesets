rule Win_Trojan_Cunning_1
{
strings:
	$a0 = { 010e1f0e07e836068db73e08bf0001b90300fcf3a480bf3008007503eb7f902e8e1e2c0033ed4d458dbf4408 }


condition:
	$a0
}