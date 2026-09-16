rule Win_Trojan_VGEN_205
{
strings:
	$a0 = { 0400f7dbf7dbcd038dbe9702ffd7ebf9e920004224cfcddb8c7cdcf88964daf8fa0ddc0ddc018d6c4df8b8de253721 }


condition:
	$a0
}