rule Win_Trojan_SillyRE_5
{
strings:
	$a0 = { e800005d83ed03b83bfccd213db0227503eb6090b448bb3800cd21731c8cc0488ec0268b1e030083 }


condition:
	$a0
}