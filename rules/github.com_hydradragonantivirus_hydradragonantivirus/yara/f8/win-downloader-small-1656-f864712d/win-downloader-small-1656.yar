rule Win_Downloader_Small_1656
{
strings:
	$a0 = { ff15204000108d8dfcfeffff83e904385f08881c08744168005000108d85f8fdffff50ffd68d85fcfeffff508d85f8fdffff50ff15644000108d85f8fdffff506802000080ff15e0400010 }


condition:
	$a0
}