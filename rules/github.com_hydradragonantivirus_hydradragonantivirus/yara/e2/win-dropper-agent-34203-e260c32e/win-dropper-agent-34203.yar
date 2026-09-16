rule Win_Dropper_Agent_34203
{
strings:
	$a0 = { bd26104000e874ffffffbf0e104000ff554883c707ff554883c708ff5548bbfc134000be59ee4100909068d65e010051ff5524 }


condition:
	$a0
}