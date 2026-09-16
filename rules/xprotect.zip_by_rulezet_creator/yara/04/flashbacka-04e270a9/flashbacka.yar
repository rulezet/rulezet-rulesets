import "hash"
rule FlashbackA
{
    meta:
        description = "OSX.Flashback.A"
        xprotect_rule = true
    condition:
        filesize <= 200000 and (
        	hash.sha1(0, filesize) == "4cca20ffe6413a34176daab9b073bcd7f78a02b9" or
            hash.sha1(0, filesize) == "2b69d70a55e6effcabe5317334c09c83e8d615eb" or
            hash.sha1(0, filesize) == "bd5e541ee0aeba084f10b1149459db7898677e40" or
            hash.sha1(0, filesize) == "033de56ba7d4e5198838530c75c7570cd5996da8" or
            hash.sha1(0, filesize) == "a99f651cdcef3766572576c5dab58ba48c0819c0" or
            hash.sha1(0, filesize) == "6da26fd20abb4815c56f638924dc82cf6ca65caf" or
            hash.sha1(0, filesize) == "ffdcd8fb4697d4c88513b99cc748e73cf50f9186" or
            hash.sha1(0, filesize) == "026107095b367d7c1249ef7ad356ecd613ebe814" or
            hash.sha1(0, filesize) == "02a35e2ef3ccdf50d0755b27b42c21e8ce857d09"
        )
}