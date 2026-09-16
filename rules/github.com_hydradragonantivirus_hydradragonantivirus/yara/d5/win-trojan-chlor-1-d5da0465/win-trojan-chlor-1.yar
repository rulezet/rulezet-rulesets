rule Win_Trojan_Chlor_1
{
strings:
	$a0 = { 33fffa8ed78be6fb8edfcd1248a31304c1e0068ec0fcb90001f3a506686100cbe85001cd19 }


condition:
	$a0
}