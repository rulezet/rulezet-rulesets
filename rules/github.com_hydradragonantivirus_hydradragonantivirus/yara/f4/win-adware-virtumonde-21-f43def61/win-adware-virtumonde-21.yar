rule Win_Adware_Virtumonde_21
{
strings:
	$a0 = { de8540deeaac8b9fe543b3ad19729424fb26e1e58cd8123ad7db4cb3780d2b391942f5ebbdc114f9b70b2fb7d1a3401e8d721c8e07cb98afd2af3c880369d6acd7c57af45d6a91b1260ecdd40915fbbe }


condition:
	$a0
}