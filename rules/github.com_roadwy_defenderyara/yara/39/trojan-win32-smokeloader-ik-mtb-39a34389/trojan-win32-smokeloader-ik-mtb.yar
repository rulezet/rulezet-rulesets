rule Trojan_Win32_Smokeloader_IK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 57 33 c9 bf 7e 07 00 00 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 3b cf 72 ea } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}