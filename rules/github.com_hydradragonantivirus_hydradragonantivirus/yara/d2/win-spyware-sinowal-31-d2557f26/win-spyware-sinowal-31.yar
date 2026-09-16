rule Win_Spyware_Sinowal_31
{
strings:
	$a0 = { 8bf085f674228d45f85056c645f845ff150410400085c074086a016a00ffd05959 }


condition:
	$a0
}