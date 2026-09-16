rule Trojan_Win32_Trickbot_RTA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 bf ab 05 00 00 f7 ff 80 c2 3d 85 f6 76 ?? 8a 01 32 c2 02 c2 88 01 83 c1 01 83 ee 01 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}