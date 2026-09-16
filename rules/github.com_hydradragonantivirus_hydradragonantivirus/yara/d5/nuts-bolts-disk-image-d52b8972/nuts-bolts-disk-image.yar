import "pe"
rule _Nuts__Bolts_Disk_Image_
{
	meta:
		description = "Nuts & Bolts Disk Image"
	strings:
		$0 = {4E 42 69 6D}
	condition:
		$0 at pe.entry_point
}