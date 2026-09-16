import "hash"
rule EleanorA
{
    meta:
        description = "OSX.Eleanor.A"
    condition:
        filesize <= 3500 and uint8(0) == 0x23 and 
        (
            hash.sha1(0, filesize) == "de642751e96b8c53744f031a6f7e929d53226321" or
            hash.sha1(0, filesize) == "1f782e84ddbf5fd76426f6f9bf3d4238d2ec9a4b"
        )
}