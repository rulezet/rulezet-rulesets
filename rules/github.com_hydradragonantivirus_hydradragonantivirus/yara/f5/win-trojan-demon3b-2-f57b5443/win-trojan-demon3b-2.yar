rule Win_Trojan_Demon3b_2
{
strings:
	$a0 = { 0f110d9993cd9dadcf01f391ac119b4391a681a66daaf80bb103d99175d8c885c4e595cf91a698963b4323d54f7645 }


condition:
	$a0
}