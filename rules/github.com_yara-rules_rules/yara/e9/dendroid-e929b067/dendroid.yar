rule Dendroid : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid RAT"
	strings:
    	$s1 = "/upload-pictures.php?"
    	$s2 = "Opened Dialog:"
    	$s3 = "com/connect/MyService"
    	$s4 = "android/os/Binder"
    	$s5 = "android/app/Service"
   	condition:
    	all of them

}