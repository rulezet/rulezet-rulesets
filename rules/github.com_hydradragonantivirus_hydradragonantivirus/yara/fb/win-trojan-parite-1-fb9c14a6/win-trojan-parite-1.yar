rule Win_Trojan_Parite_1
{
strings:
	$a0 = { 4284bd4ddaf8ff8a561356daa94ac8dca982c273dbf850658d06008dafdf84565120570061cf5000b1c5fe72db55e84725070009e47312db738a4d45758a854f }


condition:
	$a0
}