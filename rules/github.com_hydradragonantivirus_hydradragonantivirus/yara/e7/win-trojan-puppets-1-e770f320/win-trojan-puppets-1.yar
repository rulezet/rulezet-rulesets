rule Win_Trojan_Puppets_1
{
strings:
	$a0 = { 33c08ec026a118003d0000750d5807bf0001a5a5bf00011e57cb33c026a318002ea102002d81002ea302008ec0 }


condition:
	$a0
}