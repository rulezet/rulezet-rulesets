rule Win_Trojan_HH_11
{
strings:
	$a0 = { b440b952028d960601cd21e80500b43ecd21c38db62001b9130280342a464975f9c3 }


condition:
	$a0
}