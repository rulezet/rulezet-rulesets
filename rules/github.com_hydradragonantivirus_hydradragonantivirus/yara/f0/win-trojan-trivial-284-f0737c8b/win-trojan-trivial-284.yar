rule Win_Trojan_Trivial_284
{
strings:
	$a0 = { 33c9ba2700b44ecd21ba9e00b8023dcd218bd8ba0001b127b440cd21b43ecd21b44fcd2173e3c32a2e636f6d00 }


condition:
	$a0
}