import "hash"
rule MacDefenderB
{
    meta:
        description = "OSX.MacDefender.B"
        xprotect_rule = true
    strings:
    	$a = {436F6E74656E7473 [-] 496E666F2E706C697374 [-] 4D61634F53 [-] 5265736F7572636573 [-] 0000 (0AF101134A4495 | 0B20012B644D93 | 0B1F01B1239428 | 0B1F0158C4CC11) 000000000000000000000008446F776E6C6F6164506963742E706E6700000000}

    condition:
		filesize <= 1000000 and
		($a or
		hash.sha1(0, filesize) == "03fce25a7823e63139752506668eededae4d33b7" or 
		hash.sha1(0, filesize) == "0dceacd1eb6d25159bbf9408bfa0b75dd0eac181" or
		hash.sha1(0, filesize) == "1191ed22b3f3a7578e0cedf8993f6d647a7302b1" or
		hash.sha1(0, filesize) == "5fd47e23be3a2a2de526398c53bc27ebc4794e61" or
		hash.sha1(0, filesize) == "6b1b5d799bbc766f564c838c965baf2ca31502df" or
		hash.sha1(0, filesize) == "7eb5702f706e370ced910dd30f73fef3e725c2bb" or
		hash.sha1(0, filesize) == "7815c43edd431d6f0a96da8e166347f36ee9f932" or
		hash.sha1(0, filesize) == "a172738a91bada5967101e9d3d7ef2f7c058b75b" or
		hash.sha1(0, filesize) == "b350021f80ff6dacd31a53d8446d21e333e68790" or
		hash.sha1(0, filesize) == "eb876a4fd893fd54da1057d854f5043f6c144b67" or
		hash.sha1(0, filesize) == "3596070edc0badcf9e29f4b1172f00cebb863396" or
		hash.sha1(0, filesize) == "8cfce1b81e03242c36de4ad450f199f6f4d76841"
		)
}