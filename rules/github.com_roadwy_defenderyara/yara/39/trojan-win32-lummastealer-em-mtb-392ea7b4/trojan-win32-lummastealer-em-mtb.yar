rule Trojan_Win32_LummaStealer_EM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e7 01 f8 8d 4e ff 42 83 fe 01 89 ce 77 d5 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}