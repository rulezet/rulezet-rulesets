rule Win_Trojan_Muny_5
{
strings:
	$a0 = { 33c9cd213d0cf8736c2d0300502e8886c704b440b924008d960001cd2133f6bfa3033e8a8224 }


condition:
	$a0
}