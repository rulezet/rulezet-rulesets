rule Win_Trojan_Vienna_92
{
strings:
	$a0 = { 51fcb9ce0390faba74188bf24e8a048bee4d8a66002ae0886600e2f590 }


condition:
	$a0
}