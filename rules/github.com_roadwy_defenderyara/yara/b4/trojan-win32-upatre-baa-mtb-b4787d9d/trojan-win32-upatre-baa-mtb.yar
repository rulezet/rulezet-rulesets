rule Trojan_Win32_Upatre_BAA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 db 8a 06 c6 04 1f ff 20 04 1f 46 47 49 eb eb } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}