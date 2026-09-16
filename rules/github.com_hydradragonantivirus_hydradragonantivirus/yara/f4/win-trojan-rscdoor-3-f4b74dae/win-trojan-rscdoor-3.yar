rule Win_Trojan_RSCdoor_3
{
strings:
	$a0 = { 56e8137e45b1a725889f5feab5fff3ff9b01697369626c655365727665720065ffcc310002cf37ffffffffa7ee38f08b }


condition:
	$a0
}