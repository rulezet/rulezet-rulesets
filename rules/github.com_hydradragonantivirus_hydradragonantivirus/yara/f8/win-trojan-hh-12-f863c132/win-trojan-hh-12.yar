rule Win_Trojan_HH_12
{
strings:
	$a0 = { 1300b440b96e018d960601cd21e80500b43ecd21c38db62001b92f0180340d464975f9c3 }


condition:
	$a0
}