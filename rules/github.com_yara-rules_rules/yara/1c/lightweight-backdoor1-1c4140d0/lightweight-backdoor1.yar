rule Lightweight_Backdoor1
{

	strings:
		$STR1 = "NetMgStart"
		$STR2 = "Netmgmt.srg"
		
	condition:
		(uint16(0) == 0x5A4D) and all of them
}