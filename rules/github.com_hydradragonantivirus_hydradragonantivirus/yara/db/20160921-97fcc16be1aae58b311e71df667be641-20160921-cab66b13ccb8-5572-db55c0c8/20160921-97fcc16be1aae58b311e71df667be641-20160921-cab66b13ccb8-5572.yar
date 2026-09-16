rule _20160921_97fcc16be1aae58b311e71df667be641_20160921_cab66b13ccb8_5572 {
  meta:
    description = "datamaliciousorder - from files 20160921_97fcc16be1aae58b311e71df667be641.js, 20160921_cab66b13ccb843c90a2a068a082cd4ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"
    hash2       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"

  strings:
    $s1 = "{return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";}" ascii
    $s2 = "f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"V" ascii
    $s3 = " f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s4 = "eturn \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})()," ascii
    $s5 = "){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}