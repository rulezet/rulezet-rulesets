rule Win_Trojan_Mybot_8266
{
strings:
	$a0 = { 858b3cf9908092671957e013e5ed2f4e34fed41411f5cf17967ef0b9c0246ae22dcbada3272e21bbfaa0d845ed9a0bd6f4ee9d65eaabe06fcf6140f9e258f90873da1befd78e }


condition:
	$a0
}