rule Trojan_BAT_Lazy_AL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 02 00 20 01 00 00 00 fe 01 39 12 00 00 00 73 ?? ?? ?? 0a fe 0e 00 00 20 02 00 00 00 fe 0e 02 00 00 fe 0c 02 00 20 03 00 00 00 fe 01 39 26 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}