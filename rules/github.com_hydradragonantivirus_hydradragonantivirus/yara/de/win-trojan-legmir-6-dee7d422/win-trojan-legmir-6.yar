rule Win_Trojan_Legmir_6
{
strings:
	$a0 = { 46524dffffffbf774e23ff5fd23769bba7b6cb236c6567656e64206f66206d26fc0acd6972fedffaff53791b8bda0aa21136a2c35254f65c84a5ddc40320ea9023cca0df }


condition:
	$a0
}