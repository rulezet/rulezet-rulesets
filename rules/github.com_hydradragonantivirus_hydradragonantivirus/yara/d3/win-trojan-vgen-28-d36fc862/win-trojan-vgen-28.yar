rule Win_Trojan_VGEN_28
{
strings:
	$a0 = { 0dcd2133ff8edfb7024fb8024acd2fb8104abb0100cd2fb30647742be8d0fff32ea4b854028747fe50ff378c0f87cf }


condition:
	$a0
}