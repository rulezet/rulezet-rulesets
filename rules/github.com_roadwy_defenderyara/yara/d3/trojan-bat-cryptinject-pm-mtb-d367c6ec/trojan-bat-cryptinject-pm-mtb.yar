rule Trojan_BAT_CryptInject_PM_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 09 47 02 08 1f ?? 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe ?? 16 fe ?? 13 ?? 11 ?? 2d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}