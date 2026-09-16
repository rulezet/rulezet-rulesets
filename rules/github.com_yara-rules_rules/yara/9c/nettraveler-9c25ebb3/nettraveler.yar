rule NetTraveler : Family {
	meta:
		description = "Nettravelr"
		author = "Katie Kleemola"
		last_updated = "2014-07-08"
	
	condition:
		NetTravExports or NetTravStrings or NetpassStrings

}