rule Trojan_Win32_Ekstak_GAD_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 54 4c 72 00 cb b0 6e 00 00 be 0a 00 0b 33 49 b9 9a 69 6e 00 00 dc 01 00 52 99 50 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}