rule Win_Trojan_SillyRCE_4
{
strings:
	$a0 = { cd218ed9b021ba8202ccc38bd5b9ac01b440cc33d233c9b80042ccc3505351525556571ebd0002 }


condition:
	$a0
}