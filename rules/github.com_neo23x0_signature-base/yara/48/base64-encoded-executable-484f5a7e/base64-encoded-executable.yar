rule Base64_encoded_Executable : FILE {
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-05-28"
		score = 40
		id = "0bfc5916-3e63-5601-9f14-65f848c9322b"
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" 		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" 		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" 		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" 		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" 	condition:
		1 of them
		and not filepath contains "Thunderbird"
      and not filepath contains "Internet Explorer"
      and not filepath contains "Chrome"
      and not filepath contains "Opera"
      and not filepath contains "Outlook"
      and not filepath contains "Temporary Internet Files"
}