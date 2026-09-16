rule Win_Trojan_MF_5
{
strings:
	$a0 = { 7efe037502cd238a46fe8846ff8a46ff89ec5dc33054686973206973205b467269656e642d }


condition:
	$a0
}