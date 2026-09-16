rule Win_Trojan_VB_107_6
{
strings:
	$a0 = { 8bfeef2e47106f6eda69656e74506c75636c734fffffb6ed066769137203670d94c95ee58a75fd488e933e34faffe683e33f27 }


condition:
	$a0
}