rule Trojan_Win32_Strab_AMBI_MTB_2{
	meta:
		description = "Trojan:Win32/Strab.AMBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 fe 0f b6 81 ?? ?? ?? ?? c0 c8 03 32 82 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 42 01 99 f7 fe } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}