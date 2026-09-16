rule Win_Spyware_ye_117
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]72b87c498d346711b3d8fbed953262 }


condition:
	$a0
}