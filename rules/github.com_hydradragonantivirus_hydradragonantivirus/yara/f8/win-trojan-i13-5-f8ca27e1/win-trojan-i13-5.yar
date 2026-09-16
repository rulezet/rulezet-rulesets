rule Win_Trojan_I13_5
{
strings:
	$a0 = { 03014444b84158cd213d13cd744eb82135cd212e899eca012e8c86cc018cd8488ec026a103002d300093b44a1e }


condition:
	$a0
}