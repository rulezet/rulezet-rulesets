rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_5d6863feab41_4978 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash3       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash4       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash5       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "n f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"D" ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";" ascii
    $s3 = "eturn \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})()," ascii
    $s4 = "),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000()" ascii
    $s5 = "ction f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}