rule Win_Trojan_Bancos_654
{
strings:
	$a0 = { 08cb3953b24b12cede50ed774cabdb8daf9623feac275d8b042dada97cf54d454cc78d70ab130e7e61533a16057c9d8a194170093c3fe89829bfad260823ceaa955a5ac1 }


condition:
	$a0
}