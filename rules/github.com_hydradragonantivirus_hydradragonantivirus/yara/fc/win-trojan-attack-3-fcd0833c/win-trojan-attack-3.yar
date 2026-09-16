rule Win_Trojan_Attack_3
{
strings:
	$a0 = { eced89f684e9a0aca4a389c1c0c784e8889f9f8288898a736d898a466d8ac86de881efedeb898aee6c8ac86de881eeedebff81efed88e8889f9f8288f489f7f6 }


condition:
	$a0
}