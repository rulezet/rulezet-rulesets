rule Trojan_Win64_CryptInject_MYY_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b7 0c 46 4d 8d 04 46 48 8b 05 ?? ?? 08 00 48 f7 f1 66 41 89 00 48 ff 0d ?? ?? 08 00 8a 0c 25 bf 4e 00 00 2a 0d ?? ?? 08 00 2a 0d 3e 4b 08 00 49 8b 03 41 32 cc 41 88 0c 01 48 ff 05 ?? ?? 08 00 0f b6 0b 41 8b 82 2c 71 00 00 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}