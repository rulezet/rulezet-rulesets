rule Base64_encoded_Executable {
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 50
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" 		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" 		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" 		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" 		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" 	condition:
		1 of them
}