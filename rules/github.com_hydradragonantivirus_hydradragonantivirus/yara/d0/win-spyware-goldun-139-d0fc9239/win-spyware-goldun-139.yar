rule Win_Spyware_Goldun_139
{
strings:
	$a0 = { fd0b7ef20fbfc6f7d850da08a20dde4e4eea817dfacf726f8a6717c3e44618cf19ddf645180157825a6d47333ec535e5836f5503b17f08e9f1297d6f978846411c155f8575fa81dca0cec4 }


condition:
	$a0
}