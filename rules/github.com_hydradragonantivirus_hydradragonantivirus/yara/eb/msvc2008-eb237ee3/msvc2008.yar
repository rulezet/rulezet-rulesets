import "pe"
rule MSVC2008
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "9.00"
	condition:
		(pe.rich_signature.version(30729) and pe.rich_signature.version(50727) and pe.rich_signature.version(8078) and pe.rich_signature.toolid(131)) or 
		((pe.rich_signature.version(30729) or pe.rich_signature.version(21022)) and ((pe.linker_version.major == 9) and (pe.linker_version.minor == 0 )))
		
}