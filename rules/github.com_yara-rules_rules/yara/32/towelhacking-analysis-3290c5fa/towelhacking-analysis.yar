rule towelhacking_analysis
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "From static analysis"
		sample = "258c34428e214d2a49d3de776db98d26e0bd0abc452249c8be8cdbcb10218e8c"

	strings:
		$analysis_a = "LoganberryApplication"
		$analysis_b = "attachBaseContext"
		$analysis_c = "Obstetric"

	condition:
		all of them
		
}