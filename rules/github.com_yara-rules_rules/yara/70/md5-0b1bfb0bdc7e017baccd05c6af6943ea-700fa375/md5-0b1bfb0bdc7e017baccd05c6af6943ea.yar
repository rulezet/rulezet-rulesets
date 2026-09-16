rule md5_0b1bfb0bdc7e017baccd05c6af6943ea {
	
    strings: $ = /eval\([\w\d]+\(\$[\w\d]+, \$[\w\d]+\)\);/
    condition: any of them
}