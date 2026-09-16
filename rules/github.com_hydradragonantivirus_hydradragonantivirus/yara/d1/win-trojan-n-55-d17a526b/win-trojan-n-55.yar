rule Win_Trojan_N_55
{
strings:
	$a0 = { dbfa8ed3bc007c8ec4fbb98bdcba80062ae4cd13b80402cd1372f5eaf50000 }


condition:
	$a0
}