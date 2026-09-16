rule Win_Trojan_Andromeda_12
{
strings:
	$a0 = { 7503e94ffe80fc30750981fefecd7503bf3d1bfb }


condition:
	$a0
}