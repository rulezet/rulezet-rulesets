rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_74aa1eb054c4_3622 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_c745108b7e58564d28687f6e180c98c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash3       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash4       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash5       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"

  strings:
    $s1 = "f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj" ascii
    $s2 = "n\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s3 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s4 = "ction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s5 = "return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})()" ascii
    $s6 = "on f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}