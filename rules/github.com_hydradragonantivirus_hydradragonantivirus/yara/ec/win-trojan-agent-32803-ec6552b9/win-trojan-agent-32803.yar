rule Win_Trojan_Agent_32803
{
strings:
	$a0 = { 5cfa9e1d1584a60b0ec7e50590688850abac4eec5a28bd6df8ccfaef7d185f6f9a3bf11129c664655dd9cec97428da5d7b7e77862fe3fd933d420a3293bed40101 }


condition:
	$a0
}