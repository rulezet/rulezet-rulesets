rule Win_Trojan_Yard_3
{
strings:
	$a0 = { 1e060e1fe800005e83ee0856fcb8ababcd213dbaba745033ff26836d022b068cc0488ec0268b5d0383eb2b07b44acd }


condition:
	$a0
}