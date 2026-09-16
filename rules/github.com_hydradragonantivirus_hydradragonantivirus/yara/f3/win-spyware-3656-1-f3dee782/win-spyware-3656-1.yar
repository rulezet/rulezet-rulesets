rule Win_Spyware_3656_1
{
strings:
	$a0 = { 681d45f01c33342483c404578d3e81f71d45f01c }


condition:
	$a0
}