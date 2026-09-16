rule Win_Trojan_VGEN_75
{
strings:
	$a0 = { bb5a08be3601bfab03bad9044783c2034681fea20574203bf7740d3bf27409813c909075ebe80200ebe6c604cc8b }


condition:
	$a0
}