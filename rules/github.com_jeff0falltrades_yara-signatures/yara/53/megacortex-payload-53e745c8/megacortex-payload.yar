import "pe"
rule megacortex_payload {
    meta:
        author = "jeFF0Falltrades"
        reference = "https://news.sophos.com/en-us/2019/05/03/megacortex-ransomware-wants-to-be-the-one/"

    condition:
        uint16(0) == 0x5a4d and ((for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b" or pe.signatures[i].serial == "71:a0:b7:36:95:dd:b1:af:c2:3b:2b:9a:18:ee:54:cb" or pe.signatures[i].serial == "5a:59:a6:86:b4:a9:04:d0:fc:a0:71:53:ea:6d:b6:cc")) or pe.imphash() == "81da9241b26f498f1f7a1123ab76bb9d" or pe.imphash() == "ac3a9bb6fa7b3e8b91bfebe68b0d501b" or pe.imphash() == "17c56ef351018d9d9dabf0025a0394ac")
}