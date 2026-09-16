rule Win_Trojan_F3_1
{
strings:
	$a0 = { 42cd217301c30e1f33d2b96d07b440cd21c380fc4b740e3d663374052eff2e1801b8cafa }


condition:
	$a0
}