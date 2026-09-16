rule Win_Adware_GameVance_2
{
strings:
	$a0 = { 45706963506c61792047616d657320457874656e73696f6e }


condition:
	$a0
}