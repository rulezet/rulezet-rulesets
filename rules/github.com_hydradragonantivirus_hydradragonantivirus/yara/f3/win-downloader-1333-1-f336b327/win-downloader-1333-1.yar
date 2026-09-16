rule Win_Downloader_1333_1
{
strings:
	$a0 = { a07cdc6f2d6318f6646464e7d174646318ec646464672fefb57c53d570bc53d584b253d5b8b36727eda95c675fedd954 }


condition:
	$a0
}