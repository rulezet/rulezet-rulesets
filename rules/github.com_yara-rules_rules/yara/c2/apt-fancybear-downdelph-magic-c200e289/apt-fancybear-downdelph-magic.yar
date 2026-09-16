rule APT_fancybear_Downdelph_magic : Bootkit{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "APT28 downdelph magic string"
		reference = "https://www.threatminer.org/_reports/2016/eset-sednit-part3%20-%20ESET.pdf#viewer.action=download"
	strings:
		$str1 = " :3 "
	condition:
		$str1 at 0
}