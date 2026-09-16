rule Win_Trojan_JFK_1
{
strings:
	$a0 = { 33c09081ed060133db33c9e886039cf51147aec311c2d6c31114b4e79abe9aaf90af9143a56cdc6242f70bce47 }


condition:
	$a0
}