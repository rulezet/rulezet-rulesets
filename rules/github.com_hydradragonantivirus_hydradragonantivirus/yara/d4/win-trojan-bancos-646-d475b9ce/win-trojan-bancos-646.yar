rule Win_Trojan_Bancos_646
{
strings:
	$a0 = { 63deaa8be76256541bb4e34384a0264b1d36a4521ff59a6bc9d54674d7abb779a6fdf8a0b0925914ea5646cae0d4add5753a56c2bcc80c312cdd644929be81d11ad74e67 }


condition:
	$a0
}