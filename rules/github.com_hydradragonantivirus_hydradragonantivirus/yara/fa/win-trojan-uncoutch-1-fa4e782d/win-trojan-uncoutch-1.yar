rule Win_Trojan_Uncoutch_1
{
strings:
	$a0 = { b82135cd218c06????891e????1e4f8edf8b1e03001f83eb21b44a478ec7cd21b448bb2000cd2172 }


condition:
	$a0
}