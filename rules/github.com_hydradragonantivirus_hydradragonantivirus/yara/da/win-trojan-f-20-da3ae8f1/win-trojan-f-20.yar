rule Win_Trojan_F_20
{
strings:
	$a0 = { 81f766e050e42150e90e00f4e621e901005c58e621e906000fb0ffebef3858bd9002d1cd8785114905df17f7d8 }


condition:
	$a0
}