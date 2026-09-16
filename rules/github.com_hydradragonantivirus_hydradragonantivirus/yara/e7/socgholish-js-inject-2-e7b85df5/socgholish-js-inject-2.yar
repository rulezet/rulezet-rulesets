rule SocGholish_JS_Inject_2
{
	meta:
		author = "Josh Trombley "
		date_created = "9/2/2021"

	strings:
		$s0 = "new RegExp("
		$s1 = "document.createElement('script')"
		$s2 = "type = 'text/javascript'"
		$s3 = "document.getElementsByTagName('script')"
		$s4 = ".parentNode.insertBefore("
    	$s5 = "=window.atob("
    	$s6 = ".async=trye;"

	condition:
		all of them		
}