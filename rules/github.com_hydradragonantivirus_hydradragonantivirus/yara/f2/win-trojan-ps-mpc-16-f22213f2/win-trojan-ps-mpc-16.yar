rule Win_Trojan_PS_MPC_16
{
strings:
	$a0 = { 8db61a008bfebb0301 }

	$a1 = { ac8a1732c243aae2f7c3 }


condition:
	$a0 and $a1
}