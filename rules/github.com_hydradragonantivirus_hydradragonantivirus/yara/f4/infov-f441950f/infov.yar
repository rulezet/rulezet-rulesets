rule infov {
    strings:
                $connect_to_host = { 5355568BF1578B3D????????8D5E488D6E04538BCDE8????????85C075178B86EC0000008D04808D04808D0480C1E00350FFD7EBDD5F5E5D5BC3 }
        $successed = "Install service Successed\n"

    condition:
        uint16be(0) == 0x4d5a and ($connect_to_host or $successed)
}