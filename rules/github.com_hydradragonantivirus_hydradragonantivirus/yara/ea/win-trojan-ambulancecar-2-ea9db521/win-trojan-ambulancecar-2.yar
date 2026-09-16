rule Win_Trojan_AmbulanceCar_2
{
strings:
	$a0 = { 018a0788058b4701894501ffe7 }


condition:
	$a0
}