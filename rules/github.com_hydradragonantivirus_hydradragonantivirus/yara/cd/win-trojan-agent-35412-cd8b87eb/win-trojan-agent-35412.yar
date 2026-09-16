rule Win_Trojan_Agent_35412
{
strings:
	$a0 = { 8d55e34b8d4d0881c69b27000081eb62660000bbd01040004289194f588d753983 }


condition:
	$a0
}