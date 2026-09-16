rule Win_Trojan_Marina_1
{
strings:
	$a0 = { 8d978101cc58f6c1107528e83cffb4dab110cc73d40bdb7496b800012bd82bf0b48f8bd3cc }


condition:
	$a0
}