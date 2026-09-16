rule Win_Trojan_Small_3970
{
strings:
	$a0 = { be674523018d3dffd7690281efff65290289fe8d9fc008fe7f81eb4404fe7f6a0089e25252526a006a00ff15f8764000 }


condition:
	$a0
}