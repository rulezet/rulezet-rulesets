rule OpenSSL_dh_p192_c__8_byt_24_
{
strings:
	$a0 = { d4a0ba0250b6fd2ec626e7efd637df76c716e22d0944b88b }

condition:
	$a0
}