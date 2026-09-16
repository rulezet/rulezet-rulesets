rule bin_Client {
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f91a5b46d155cacf0cc6673a2a5461b"
	strings:
		$s0 = "Recieved respond from server!!"
		$s4 = "packet door client"
		$s5 = "input source port(whatever you want):"
		$s7 = "Packet sent,waiting for reply..."
	condition:
		all of them
}