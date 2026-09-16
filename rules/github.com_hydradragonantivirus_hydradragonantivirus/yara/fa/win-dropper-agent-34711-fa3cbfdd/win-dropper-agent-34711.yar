rule Win_Dropper_Agent_34711
{
strings:
	$a0 = { 5c77696e686c702e657865[0-27]5c63757272656e7476657273696f6e5c72756e }


condition:
	$a0
}