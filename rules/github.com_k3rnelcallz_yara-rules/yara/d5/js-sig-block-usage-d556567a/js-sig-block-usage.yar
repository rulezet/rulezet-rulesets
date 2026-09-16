rule js_sig_block_usage 
{
	meta: 
		author = "k3rnelcallz"
		sha = "5d26c74c808d39201faa95bc10100843df0d0931ff5c5b0b4de28f9277ac2d36"
		mod_date = "12-13-25"
		description = "signature block with random with function in between"
		source = "mbazaar"
        samples = "4+"
        tags = "Family: Rhadamanthys"
		
	strings: 
		$sig_block_marker1 = "// SIG // Begin signature block" ascii wide
		$sig_block_marker2 = "// SIG // End signature block" ascii wide
		$f = "function" ascii wide

	condition: 
		any of ($sig_block_marker*)
		and $f
}