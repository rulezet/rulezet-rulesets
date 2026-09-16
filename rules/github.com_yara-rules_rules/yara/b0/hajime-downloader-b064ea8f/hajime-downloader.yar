import "hash"
rule Hajime_DOWNLOADER : MALW
{
meta:
description = "Hajime Botnet - Downloader"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "f1cc4275d29b7eaa92a4cca015af227e"
SHA1 = "e649e0d97cc23c8c4bbd78be430a49a4babbccd7"
ref1 = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
ref2 = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

strings:
	$get = "GET /r/sr.arm5 HTTP/1.0"
	$nif = "NIF\n"


condition:
	$get and $nif and filesize < 700KB and hash.sha1(0,filesize) == "e649e0d97cc23c8c4bbd78be430a49a4babbccd7"

}