rule SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15_
{
strings:
	$a0 = { 3021300906052b0e03021a05000414 }

condition:
	$a0
}