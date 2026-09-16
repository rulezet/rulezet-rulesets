rule Win_Trojan_IRCBot_273
{
strings:
	$a0 = { ee709b5f2042fade5a20cc655b1127a3895b4de864a44aab670179a0fa2eaa4ced5bb8976da4b7c6ba04985bf44b46c1c102f46b901b90473638a2289092bbc0fe77a35a3f33b5a18a8b2f88c66c05d5 }


condition:
	$a0
}