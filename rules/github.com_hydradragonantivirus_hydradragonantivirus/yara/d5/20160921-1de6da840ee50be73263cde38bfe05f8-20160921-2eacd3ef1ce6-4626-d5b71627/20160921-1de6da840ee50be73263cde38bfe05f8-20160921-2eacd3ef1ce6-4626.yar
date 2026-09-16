rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_2eacd3ef1ce6_4626 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash4       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = " \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s2 = "urn \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s3 = "eturn \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})()," ascii
    $s4 = "00(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\"" ascii
    $s5 = "urn \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}