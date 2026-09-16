rule Win_Trojan_Waledac_34
{
strings:
	$a0 = { 662bd980eecc6623fad2cdf7d90bf7661bf3e89f1000004dd5a06abed2 }


condition:
	$a0
}