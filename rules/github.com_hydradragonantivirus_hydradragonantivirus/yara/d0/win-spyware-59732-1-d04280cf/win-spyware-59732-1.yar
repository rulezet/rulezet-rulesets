rule Win_Spyware_59732_1
{
strings:
	$a0 = { 558bec81c4dcfeffff60837d0c010f }

	$a1 = { 504f53545f55524c31 }

	$a2 = { 514851584258005f4e414d45 }


condition:
	$a0 and $a1 and $a2
}