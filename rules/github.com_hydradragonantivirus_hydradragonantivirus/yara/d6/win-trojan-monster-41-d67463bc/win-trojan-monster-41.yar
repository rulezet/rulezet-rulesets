rule Win_Trojan_Monster_41
{
strings:
	$a0 = { 8074facd8074fdcdeb00b0cdb95f023130048be2fb }


condition:
	$a0
}