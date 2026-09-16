rule Dendroid_2 : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid evidences via Droidian service"
	strings:
    	$a = "Droidian"
    	$b = "DroidianService"
   	condition:
    	all of them

}