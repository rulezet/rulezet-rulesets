rule Win_Trojan_JTD_1
{
strings:
	$a0 = { 35cd2126817f03b821743126817f0535cd74298cc133c08ec0be270526c604ea26895c0126894c038ccb8edbb821 }


condition:
	$a0
}