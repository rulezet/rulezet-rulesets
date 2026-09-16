rule Win_Trojan_Locust_2
{
strings:
	$a0 = { 36e643b07fe640e6408b36010181c6fa00bf00018b0489058a4402884502b88ac1cd2f3cff7502eb71b44abb00 }


condition:
	$a0
}