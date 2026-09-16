rule android_metasploit : android
{
	meta:
		author = "https://twitter.com/plutec_net"
		description = "This rule detects apps made with metasploit framework"
		sample = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"

	strings:
		$a = "*Lcom/metasploit/stage/PayloadTrustManager;"
		$b = "(com.metasploit.stage.PayloadTrustManager"
		$c = "Lcom/metasploit/stage/Payload$1;"
		$d = "Lcom/metasploit/stage/Payload;"

	condition:
		all of them
		
}