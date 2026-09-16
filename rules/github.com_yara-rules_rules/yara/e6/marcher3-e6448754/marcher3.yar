rule marcher3
{
	meta:
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/890"
		sample1 = "087710b944c09c3905a5a9c94337a75ad88706587c10c632b78fad52ec8dfcbe"
		sample2 = "fa7a9145b8fc32e3ac16fa4a4cf681b2fa5405fc154327f879eaf71dd42595c2"
	strings:
		$a = "certificado # 73828394"
		$b = "A compania TMN informa que o vosso sistema Android tem vulnerabilidade"
		
	condition:
		all of them
}