rule Win_Trojan_Kitana_4
{
strings:
	$a0 = { 800041b703cd13c747fe55aab80203b701cd13c30e1fff0e1304cd12b176d3c08ec033fff3a4fd }


condition:
	$a0
}