rule Win_Dropper_Agent_34372
{
strings:
	$a0 = { 558bec68f014400068ff144000e8cfffffffe8f2fbffffe896feffffe848ffffff }


condition:
	$a0
}