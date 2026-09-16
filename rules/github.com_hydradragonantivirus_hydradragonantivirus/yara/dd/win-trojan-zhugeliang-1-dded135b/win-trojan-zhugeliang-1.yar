rule Win_Trojan_Zhugeliang_1
{
strings:
	$a0 = { 727d2a4d308e8f3681c543af49ca898e8e02d29002d2ac02d2a8bd5500553a8a43940f749e88fb93 }


condition:
	$a0
}