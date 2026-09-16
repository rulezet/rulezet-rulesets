rule Win_Trojan_Lunacy_1
{
strings:
	$a0 = { 197340be40a7ba567b54c135ce6975cf0d72ba560731cd75375bf87b03735bf8630173ba565bd617 }


condition:
	$a0
}