rule Win_Trojan_Knorkator_1
{
strings:
	$a0 = { b83030cd213d030375063bd87502eb59b452cd21268b47fe33f68ed8803c5a74088bd803440340ebf1837c03 }


condition:
	$a0
}