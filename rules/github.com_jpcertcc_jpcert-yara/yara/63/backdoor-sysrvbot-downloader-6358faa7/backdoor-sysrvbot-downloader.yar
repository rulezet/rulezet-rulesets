rule backdoor_SysrvBot_downloader {
    meta:
        description = "downloader used by SysrvBot"
        author = "JPCERT/CC Incident Response Group"
        hash = "a1fbaee0915edd8568fcea9868fd511adb43faf93bd0abd63788a61febcff13b"

    strings:
        $s1 = "echo \"Detected Zen4 CPU\"" ascii
        $s2 = "key $user@$host \"(curl $cc/" ascii
        $s3 = "$i/hugepages/hugepages-1048576kB/nr_hugepages" ascii

    condition:
        all of them
}