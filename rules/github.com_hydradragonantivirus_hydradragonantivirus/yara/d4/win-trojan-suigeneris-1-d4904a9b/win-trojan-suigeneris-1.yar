rule Win_Trojan_SuiGeneris_1
{
strings:
	$a0 = { cd2181f953477452909090b82135cd212e891eab012e8c06ad018cd8488ec026a103002d260093b44a1e07cd21 }


condition:
	$a0
}