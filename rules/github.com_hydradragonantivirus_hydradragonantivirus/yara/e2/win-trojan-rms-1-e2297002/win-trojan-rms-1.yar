rule Win_Trojan_RMS_1
{
strings:
	$a0 = { f92e5e02a227272aa23f392a91287ec1f0d79d17e408a227252aa23f7f2ba7377b2b91286ac1ead7 }


condition:
	$a0
}