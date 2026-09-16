rule Win_Spyware_Banker_5882
{
strings:
	$a0 = { cd0c5e5ee5ed2fae6b035b23fbfb656707685bc8f1abcd4fafb55022cfc9854dc35867fc9b524811644ed736b3affcb1a530c0ce09abc08a1a7e6e5bd779e36f432157bb }


condition:
	$a0
}