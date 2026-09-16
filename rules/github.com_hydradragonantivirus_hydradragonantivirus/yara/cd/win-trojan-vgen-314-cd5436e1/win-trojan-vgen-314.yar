rule Win_Trojan_VGEN_314
{
strings:
	$a0 = { 023dbaf201cd2193b8024233c933d2cd2187ca8bd083ea0483d90183c101b80042cd21b92d01be0001e86400890e13 }


condition:
	$a0
}