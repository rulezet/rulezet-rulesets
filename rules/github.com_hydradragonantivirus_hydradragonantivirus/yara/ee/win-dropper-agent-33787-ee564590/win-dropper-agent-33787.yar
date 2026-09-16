rule Win_Dropper_Agent_33787
{
strings:
	$a0 = { 566894110001e8e0feffff6a018bf8576a6853e8a4fcffff565656575656ff159410000183bdecfeffff055b750f }


condition:
	$a0
}