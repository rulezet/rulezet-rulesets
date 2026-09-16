rule Win_Trojan_Nazi_1
{
strings:
	$a0 = { 9a000053005589e581ec0003bf77010e57bf1e011e57b8ff00509afd0853009aaa08530009c0745e9aaa0853008846ff }


condition:
	$a0
}