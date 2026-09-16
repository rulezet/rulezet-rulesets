rule Trojan_Win32_Dridex_RAA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba b4 12 00 00 ba bc 01 00 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}