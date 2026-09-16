rule RAT_QRat
{
	meta:
		author = "Kevin Breen @KevTheHermit"
		date = "01.08.2015"
		description = "Detects QRAT"
		reference = "http://malwareconfig.com"
		maltype = "Remote Access Trojan"
		filetype = "jar"

		id = "2ee645a3-1e01-513c-a636-098e445adeca"
	strings:
		$a0 = "e-data"
		$a1 = "quaverse/crypter"
		$a2 = "Qrypt.class"
		$a3 = "Jarizer.class"
		$a4 = "URLConnection.class"

	condition:
		4 of them
}