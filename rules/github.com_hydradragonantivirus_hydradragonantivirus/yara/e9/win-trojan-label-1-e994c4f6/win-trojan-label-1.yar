rule Win_Trojan_Label_1
{
strings:
	$a0 = { ed8eddc41dbf7402895dfc8c45feb4 }


condition:
	$a0
}