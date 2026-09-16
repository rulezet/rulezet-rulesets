rule Win_Trojan_L_13
{
strings:
	$a0 = { be1801b9370481e91801268a02345e26880246e2f5c3 }


condition:
	$a0
}