rule Trojan_BAT_CryptInject_AD_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {28 10 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a fe ?? 00 00 fe ?? 00 00 28 ?? 00 00 06 dd ?? 00 00 00 26 dd 00 00 00 00 2a } 		$a_02_1 = {28 10 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 de ?? 26 de 00 2a } 		$a_02_2 = {7e 0c 00 00 04 28 0f 00 00 06 28 ?? 00 00 0a 28 06 00 00 0a } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}