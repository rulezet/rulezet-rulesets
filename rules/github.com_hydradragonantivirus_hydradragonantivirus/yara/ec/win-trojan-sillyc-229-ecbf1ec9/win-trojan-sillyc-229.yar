rule Win_Trojan_SillyC_229
{
strings:
	$a0 = { 8b75588d5552b44ecd21b15a8d559eb8023dcd21722293b6feb43fcd21b002e82200894558b440cd2132c0e81600 }


condition:
	$a0
}