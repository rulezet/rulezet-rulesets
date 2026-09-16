rule Win_Trojan_SillyC_91
{
strings:
	$a0 = { 2e8b1e010181c3f900bf620003fbb8fe002bc78905fc8bf3bf0001b90400f3a4be8000bfc80003fbb98000f3a4b90200ba040003d3b44ecd21720fa19a003d00 }


condition:
	$a0
}