rule Win_Trojan_CyberWarrior_4
{
strings:
	$a0 = { 5d83ed032ec686190900e83c0706b452cd21268b47fe072e89866c09b430bb1313cd213d77777503e9a4003c05724db8 }


condition:
	$a0
}