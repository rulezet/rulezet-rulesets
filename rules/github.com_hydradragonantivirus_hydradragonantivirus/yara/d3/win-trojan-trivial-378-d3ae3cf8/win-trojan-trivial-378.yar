rule Win_Trojan_Trivial_378
{
strings:
	$a0 = { fab456268865fe5fcd217219b43c5a52b102cd210e1f93b440b95c00ba0001cd21b43ecd21 }


condition:
	$a0
}