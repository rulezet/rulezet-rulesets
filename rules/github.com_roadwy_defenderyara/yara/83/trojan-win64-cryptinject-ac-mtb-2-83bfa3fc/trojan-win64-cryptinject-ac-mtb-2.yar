rule Trojan_Win64_CryptInject_AC_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af ca 89 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b 50 10 0f af d1 89 50 10 8b 48 34 81 e9 ?? ?? ?? ?? 31 48 28 41 8b c8 41 0f af c8 41 ff c0 01 88 ?? ?? ?? ?? 44 3b 40 5c 76 ae } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}