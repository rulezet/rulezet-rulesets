rule Trojan_Win32_StealC_SZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 38 83 ?? 0f 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d 85 f0 ?? ff ff 50 8d 8d fc ?? ff ff 51 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}