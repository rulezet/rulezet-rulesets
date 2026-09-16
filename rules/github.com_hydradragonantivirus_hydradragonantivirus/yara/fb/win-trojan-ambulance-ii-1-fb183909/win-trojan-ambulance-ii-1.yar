rule Win_Trojan_Ambulance_II_1
{
strings:
	$a0 = { ddcd2180fccc75073cc07203e9ce00b80935cd212e89 }


condition:
	$a0
}