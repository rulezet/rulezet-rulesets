rule Trojan_Win32_Stealc_GNT_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4d fc 8b 45 08 30 0c 07 47 3b fb ?? ?? 5e 5f 83 fb } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}