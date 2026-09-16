rule Win_Trojan_VGEN_70
{
strings:
	$a0 = { 15f803eb7c00f881cf2bc942904a76007600d1dd81eefefd760023f8f7dd56d1d581eec34ef6de81caa789c36d2e }


condition:
	$a0
}