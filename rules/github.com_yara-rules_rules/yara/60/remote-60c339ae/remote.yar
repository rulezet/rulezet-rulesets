rule Remote : Family Surtr Variant Remote {
	meta:
		description = "identifier for remote"
		author = "Katie Kleemola"
		last_updated = "07-25-2014"
	
	condition:
		RSharedStrings and RemoteStrings
}