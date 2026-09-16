rule Win_Trojan_L_30
{
strings:
	$a0 = { e80f005bb94110ba0001b440cd21e80100c3bb38018a2732260a0188274381fb79117e01c3f873ed }


condition:
	$a0
}