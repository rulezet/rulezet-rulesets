rule Win_Trojan_Agent_33075
{
strings:
	$a0 = { 3dcc5652d621b60c2fc39f9eeacaa5ffff0dd108706f42d79dec90e2fc099ca1cb3c1c6b5fc12f2cf45f2508383b1d674d8c7d0e1ebfd4dfaa160dee3cc48cf47e2141ffb81101ffff37 }


condition:
	$a0
}