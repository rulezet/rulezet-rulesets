rule Win_Trojan_Rajaat_4
{
strings:
	$a0 = { 8ed38edbbc007c54fbbe1304ff0cadb106d3e08ec05e89df5706b8280050b90001a5e2fdcb2ec606140200bf0c }


condition:
	$a0
}