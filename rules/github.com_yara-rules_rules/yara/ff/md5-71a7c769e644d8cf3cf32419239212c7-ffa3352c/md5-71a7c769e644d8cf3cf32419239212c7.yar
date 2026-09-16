rule md5_71a7c769e644d8cf3cf32419239212c7 {
	
    strings: $ = /\$GLOBALS\['[\w\d]+'\]\(\$GLOBALS\['[\w\d]+'\]/
    condition: any of them
}