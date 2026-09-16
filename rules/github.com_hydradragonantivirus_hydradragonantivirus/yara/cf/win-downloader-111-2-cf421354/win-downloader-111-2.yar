rule Win_Downloader_111_2
{
strings:
	$a0 = { 0e465731e4f34f8ef1b69fba21bedae60ccca09e0e465331e4db4f8ef1b69fba4df41a32f0335fce7a76a391af68960da4b8b34f1d7356cef1600999c2e8e6f9f3335ffd31bee20f07cca0466cf3a9310ec0 }


condition:
	$a0
}