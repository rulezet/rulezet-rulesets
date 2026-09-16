rule Win_Dropper_Agent_34353
{
strings:
	$a0 = { 33c055685324141364ff30648920b864241413e8cffeffff8d8dc0feffffba9c241413b8ac241413e82afdffff8b85c0feffffe88bf8ffff50e809fcffff }


condition:
	$a0
}