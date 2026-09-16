rule Trojan_Win32_AgentTesla_A_MTB_5{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 51 fa f1 4b 6d ec fb 9f d9 6f 9b ea 37 df 0a 80 13 27 4e fa a3 a0 96 47 d9 8b d6 a9 75 17 02 40 3d a9 37 f5 18 65 2f 1a 03 8d 85 c6 44 63 43 00 a0 22 e5 06 40 4b f3 0e 53 69 e3 d2 91 26 8e da db fe a4 ed de d5 6a cd db 5b ac d0 4f 5b eb 1e ff 7a 1c bd 68 dd 85 3e d4 93 7a 8b a3 97 42 69 6c 0a fd 10 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}