rule APT_MAL_CN_Wocao_keylogger_py {
    meta:
        description = "Strings from Python keylogger"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "f7b5ec1b-669e-5e7d-a9d3-011d212eb363"
    strings:
        $a = "c:\\windows\\temp\\tap.tmp"
        $b = "c:\\windows\\temp\\mrteeh.tmp"
        $c = "GenFileName"
        $d = "outfile"
        $e = "[PASTE:%d]"

    condition:
        3 of them
}