rule Win_Trojan_Gen_244
{
strings:
	$a0 = { 91b0c5750a076e1400600d34fe89ec5dc3032a2e2a0536022e2efa2cbf1602f48ffa100100 }


condition:
	$a0
}