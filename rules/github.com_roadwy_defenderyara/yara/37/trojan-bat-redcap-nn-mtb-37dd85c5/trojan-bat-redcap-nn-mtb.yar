rule Trojan_BAT_Redcap_NN_MTB{
	meta:
		description = "Trojan:BAT/Redcap.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 0b 61 20 95 ?? ?? ?? 07 61 0b 0a ?? ?? ?? ?? ?? 07 5a 0b 02 07 ?? ?? ?? ?? ?? 61 0b 02 07 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}