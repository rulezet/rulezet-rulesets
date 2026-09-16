rule Win_Trojan_Yerk_1
{
strings:
	$a0 = { d2cd2189f281c2a201b90500b440cd2189f2b97201b440cd218b84c401050501a30101b8 }


condition:
	$a0
}