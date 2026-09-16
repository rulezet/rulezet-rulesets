rule Win_Downloader_Swizzor_319
{
strings:
	$a0 = { 3936ae7ba759630cc01097c5e74656c419bdef11458aed11e64f655580d3bba397cfbc91bea8ed8325852ccf5977208e }


condition:
	$a0
}