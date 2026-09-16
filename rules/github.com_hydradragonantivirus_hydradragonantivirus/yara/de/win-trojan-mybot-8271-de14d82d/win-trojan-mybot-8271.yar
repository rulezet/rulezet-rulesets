rule Win_Trojan_Mybot_8271
{
strings:
	$a0 = { f6562213961c07a92501ebaefe2f7f45f36a21c18c56a272ea645532a629f56ac695fa74135c6a4f8c7c160643fca9edbd58645febdf7dfe42c1907aacbe1a1c26f0b8997a6f }


condition:
	$a0
}