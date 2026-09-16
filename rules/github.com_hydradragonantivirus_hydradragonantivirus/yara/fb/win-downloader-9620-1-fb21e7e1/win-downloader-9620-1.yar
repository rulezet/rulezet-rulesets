rule Win_Downloader_9620_1
{
strings:
	$a0 = { 53516a00682c381413e8eafcffff68f4010000e8c8fcffff546a00685c381413e8e3fcffff50e8e5fcffff8b0424506a0068ff0f1f00e89dfcffff8bd8ba7c3614138bc3e853ffffff53e859fcffff5a5b }


condition:
	$a0
}