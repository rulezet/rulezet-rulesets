rule Win_Trojan_Eumel_20
{
strings:
	$a0 = { 7303e9ce00b8023d31868602ba82facd2193b80242e8cf003de9037c163dfff97c11b80057cd }


condition:
	$a0
}