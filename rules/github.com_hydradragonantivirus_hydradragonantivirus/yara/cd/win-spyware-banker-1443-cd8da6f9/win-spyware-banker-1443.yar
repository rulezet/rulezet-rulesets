rule Win_Spyware_Banker_1443
{
strings:
	$a0 = { 56289d0d968b97a96905b50983443c7de5c7ba6afbbe0c2793c271aee6b65d296fb9122cdad20acc2ae6d1cf20011ffb13e7607c5c2fb6308605434e87ac421cf19e432d }


condition:
	$a0
}