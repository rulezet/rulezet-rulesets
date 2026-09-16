rule Win_Downloader_Small_3297
{
strings:
	$a0 = { b658b5079903961acefb461ec69ef4de2be1ed0d8b91a708fe3450cbaa04173939371a4aba58a265eec0505408383a50aac06c47e451b60c9d35 }


condition:
	$a0
}