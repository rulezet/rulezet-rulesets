rule Win_Trojan_IRCBot_625
{
strings:
	$a0 = { b143bfdf26d1c2d27095dafe01c8b8ee26eb030433000c21412b42220d42168103ec44bba0b523f213c040b86007c71ed40e92ccdc53cf7ed18da36acad9db84cb785fb433451f87893fe8201aed }


condition:
	$a0
}