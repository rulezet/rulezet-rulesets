rule Trojan_Win64_CryptInject_MA_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f af 4f 4c 41 8b d1 c1 ea 08 88 14 01 ff 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 48 40 03 4f 30 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}