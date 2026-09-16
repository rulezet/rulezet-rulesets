rule Win_Trojan_Agent_32818
{
strings:
	$a0 = { da264b583b0ddf8757b936a8f76b9b5fec24e35101fc1c1a634160385eeee0eaa512afef5c07b58569cb1a0e70c4566d12295ce5aa7560c53224be7462facf4208 }


condition:
	$a0
}