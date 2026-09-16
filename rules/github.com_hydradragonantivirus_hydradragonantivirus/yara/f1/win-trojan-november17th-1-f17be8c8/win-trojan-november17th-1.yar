rule Win_Trojan_November17th_1
{
strings:
	$a0 = { 04a801741180fc43740c3d004b740fe9260259e9f001 }


condition:
	$a0
}