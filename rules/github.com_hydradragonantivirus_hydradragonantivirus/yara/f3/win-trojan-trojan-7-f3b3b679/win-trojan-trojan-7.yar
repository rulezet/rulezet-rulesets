rule Win_Trojan_Trojan_7
{
strings:
	$a0 = { 173bd1e1c436ec3d30802fcfb465ef07ebc0d03394647d9aee3fa38408da4f9f6f92f47533524c4b7e7e8e85a5c28bc4ea5edee435e3b229ae455582c818aa25b5c5983a3f4d64242ae1ee64b46303a25233efab }


condition:
	$a0
}