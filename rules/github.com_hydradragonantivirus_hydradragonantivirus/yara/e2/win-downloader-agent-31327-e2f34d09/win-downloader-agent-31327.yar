rule Win_Downloader_Agent_31327
{
strings:
	$a0 = { ccf0161c00ef63636170702e65786500736d633451104b7a6c00c0ad13005a4f4e45414c41 }


condition:
	$a0
}