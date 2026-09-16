rule Win_Downloader_653_1
{
strings:
	$a0 = { 14dbe188dcf7c77dc80d78eaf4b3fa8d216e0f376bb498448cc164c0837ea7bf15cd4e05e6b5c5ae10548ba24e553ee8d723e8bc1b8f9cb8bfddba807c702b9aae905b1727be327868df061153e35065 }


condition:
	$a0
}