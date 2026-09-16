rule Win_Trojan_Mybot_7222
{
strings:
	$a0 = { 28a6612d760d81ea3e2f66aedd3a4cd9bf7ca97d2644edab15f3397525a49b156009fb4f188654a38eaa60c103b5ed3ad9df44b502acadf15356892da30209e7d546baa2b8d5dc4bbdccc1c2ca46 }


condition:
	$a0
}