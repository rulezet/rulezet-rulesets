rule Win_Spyware_Sinowal_34
{
strings:
	$a0 = { 68801040008d85e8fdffff50ffd76a008d85e8fdffff50ff1520104000e8c3010000 }


condition:
	$a0
}