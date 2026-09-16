rule Win_Trojan_Izhevsk_1
{
strings:
	$a0 = { b80000e8cf00b81a012e030661062d03002ea3fa08baf908b90800b440e8c500ba0000b80200e8ac }


condition:
	$a0
}