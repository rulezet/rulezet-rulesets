rule Win_Trojan_HBT_1
{
strings:
	$a0 = { 0242b90000ba0000cd212d03002ea31b011eb80040b98a010e1fba0001cd211f }


condition:
	$a0
}