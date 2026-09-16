rule Trojan_Win32_Ursnif_AH_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 8b 39 81 fb ?? ?? ?? ?? 75 ?? 8d 8a ?? ?? ff ff 66 03 c1 8b 4c 24 10 66 a3 ?? ?? ?? 00 83 44 24 10 04 81 c7 78 e0 3a 01 89 39 8d 4b 49 8d 0c 51 03 f1 8b 0d ?? ?? ?? 00 8d 0c b1 03 ce 83 6c 24 14 01 0f b7 d1 0f 85 ?? ff ff ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}