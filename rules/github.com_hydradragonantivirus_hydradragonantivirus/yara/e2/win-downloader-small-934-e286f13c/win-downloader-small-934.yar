rule Win_Downloader_Small_934
{
strings:
	$a0 = { 6b73c7cc6975876db70373d065626c6b2a8c2f6dcc7dbb6b6d6ea42e7478740da55c76ef3ecced673031116d70373f03494e535436c898f1414c4c00b19f1b87 }


condition:
	$a0
}