rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_c1ad71fea9bd_5617 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f0" ascii
    $s2 = "(),(function f000(){return \"Yi\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s3 = "tion f000(){return \"ZFe\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){retur" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\"" ascii
    $s5 = "KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}