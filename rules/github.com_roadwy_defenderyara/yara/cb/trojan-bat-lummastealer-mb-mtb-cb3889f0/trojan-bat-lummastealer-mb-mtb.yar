rule Trojan_BAT_LummaStealer_MB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 72 ?? ?? ?? 70 a2 25 18 11 02 a2 a2 a2 38 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}