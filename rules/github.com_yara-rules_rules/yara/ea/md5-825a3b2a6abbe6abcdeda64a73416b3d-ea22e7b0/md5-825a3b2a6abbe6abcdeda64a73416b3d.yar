rule md5_825a3b2a6abbe6abcdeda64a73416b3d {
	
    strings: $ = /[o0O]{3}\("fsockopen"\)/
    condition: any of them
}