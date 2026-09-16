import "hash"
rule FlashbackB
{
    meta:
        description = "OSX.Flashback.B"
        xprotect_rule = true
    condition:
        filesize <= 200000 and (
            hash.sha1(0, filesize) == "fd7810b4458a583cca9c610bdf5a4181baeb2233" or
            hash.sha1(0, filesize) == "7004aec6b8193b8c3e8032d720dc121b23b921b7" or
            hash.sha1(0, filesize) == "b87a94ddd93fc036215056fbbed92380eefcadc2" or
            hash.sha1(0, filesize) == "3f40c8d93bc7d32d3c48eedacc0cd411cf273dba"
        ) or
        filesize <= 300000 and (
            hash.sha1(0, filesize) == "e266dd856008863704dd9af7608a58137d8936ba" or
            hash.sha1(0, filesize) == "7b6d5edf04a357d123f2da219f0c7c085ffa67fc" or
            hash.sha1(0, filesize) == "284484b13022e809956bb20b6ba741bd2c0a7117"
        )
}