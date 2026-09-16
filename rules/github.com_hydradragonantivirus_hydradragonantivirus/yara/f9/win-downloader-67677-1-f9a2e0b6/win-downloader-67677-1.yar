rule Win_Downloader_67677_1
{
strings:
	$a0 = { 2f736572636e632e68746d }

	$a1 = { 51514c4f47494e3a }

	$a2 = { 55534552434f4445 }

	$a3 = { 72756e }

	$a4 = { 5461736b626172437265 }

	$a5 = { 4261736963 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}