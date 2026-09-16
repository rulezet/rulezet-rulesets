rule Trojan_Win64_VidarStealer_ABA_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 48 63 c8 48 8d 54 24 ?? 48 03 d1 0f b6 0a 41 88 0c 18 44 88 0a 41 0f b6 14 18 49 03 d1 0f b6 ca 0f b6 54 0c ?? 30 17 48 ff c7 49 83 ea } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}