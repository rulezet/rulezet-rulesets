rule Win_Trojan_Dumb_8
{
strings:
	$a0 = { 4998058d0cf4119013f70798e9da23f446c4b9d176f43efc35c80bfe98324125b7888553bb5ab5f4 }


condition:
	$a0
}