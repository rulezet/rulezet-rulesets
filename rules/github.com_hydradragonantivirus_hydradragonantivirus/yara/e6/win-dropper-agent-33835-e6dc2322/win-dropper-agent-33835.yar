rule Win_Dropper_Agent_33835
{
strings:
	$a0 = { 6f70656e000000005c }

	$a1 = { 2225735c72756e646c6c66726f6d77 }


condition:
	$a0 and $a1
}