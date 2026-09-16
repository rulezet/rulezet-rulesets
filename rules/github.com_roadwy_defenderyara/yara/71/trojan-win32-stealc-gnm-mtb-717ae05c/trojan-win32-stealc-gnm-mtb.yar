rule Trojan_Win32_StealC_GNM_MTB{
	meta:
		description = "Trojan:Win32/StealC.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 46 89 45 fc 83 6d fc 46 8a 45 fc 30 04 1f 47 3b 7d } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}