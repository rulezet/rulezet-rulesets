rule Win_Trojan_Antibase_1
{
strings:
	$a0 = { 505389265e088c1660080e17bc09012ea108085b33d8535b81fc070872f58e1660088b265e08 }


condition:
	$a0
}