rule Win_Trojan_Happytime_1
{
strings:
	$a0 = { 69616d736f72727921686170707974696d65 }

	$a1 = { 633a5c68656c702e68746d }

	$a2 = { 5c756e7469746c65642e68746d }


condition:
	$a0 and $a1 and $a2
}