rule sig_20160525_77eb6c6ac468bfd75bc4ea79461636c0 {
  meta:
    description = "datamaliciousorder - file 20160525_77eb6c6ac468bfd75bc4ea79461636c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e39e62fd064532145f08ca7e8f49475715cb6d3d47e8a68f8a2dc4ebb6990e36"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]rerednern + cthn[eixodb    \\n\\n;)2 * 1 ,ssor" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}