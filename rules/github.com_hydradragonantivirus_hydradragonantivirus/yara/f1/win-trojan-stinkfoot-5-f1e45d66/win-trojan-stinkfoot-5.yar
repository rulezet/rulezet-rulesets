rule Win_Trojan_Stinkfoot_5
{
strings:
	$a0 = { 1e8501b9f603b440c606720100cd21 }


condition:
	$a0
}