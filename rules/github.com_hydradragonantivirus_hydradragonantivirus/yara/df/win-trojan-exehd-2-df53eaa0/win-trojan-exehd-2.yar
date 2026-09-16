rule Win_Trojan_ExeHd_2
{
strings:
	$a0 = { 81bff40144697502eb6f2681bfb1008cae746626813f4d5a750e26837f0639770726807f0820 }


condition:
	$a0
}