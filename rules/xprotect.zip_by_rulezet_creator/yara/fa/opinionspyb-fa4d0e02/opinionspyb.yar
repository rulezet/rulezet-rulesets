import "hash"
rule OpinionSpyB
{
    meta:
        description = "OSX.OpinionSpy.B"
    condition:
		filesize <= 9000000 and hash.sha1(0, filesize) == "a0d0b9d34f07c7d99852b9b833ba8f472bb56516"
}