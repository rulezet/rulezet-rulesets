rule Win_Trojan_First_1
{
strings:
	$a0 = { 3df401721f050001a31501b440b95701cd217210b8004233c9cd21b440b10dba1101cd21b43e }


condition:
	$a0
}