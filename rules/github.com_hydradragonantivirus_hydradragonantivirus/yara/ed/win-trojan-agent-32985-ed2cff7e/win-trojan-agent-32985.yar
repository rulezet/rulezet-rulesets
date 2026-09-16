rule Win_Trojan_Agent_32985
{
strings:
	$a0 = { 144b6739a5998cf6d4cf4c4a5a054c434a89eae00d5a7daf6c1701d030688319e128e77cad638e1d9cbc9da720aa1e9efe2afcc5db957dd7fe330f4ffdf62a9b66fcfeb4dc7c3ddd07ffad219158 }


condition:
	$a0
}