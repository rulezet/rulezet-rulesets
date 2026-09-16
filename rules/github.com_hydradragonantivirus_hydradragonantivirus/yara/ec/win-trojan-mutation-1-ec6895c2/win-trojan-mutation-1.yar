rule Win_Trojan_Mutation_1
{
strings:
	$a0 = { a36805b8004233c933d2cd21a1b305050001a36f05b440b90700ba6e05cd21b8024233c933 }


condition:
	$a0
}