rule _20160921_aa105be6eeb7f536b3fae098f4cc14ed_20160921_d4f0c091f748_5619 {
  meta:
    description = "datamaliciousorder - from files 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = " f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s2 = "unction f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s3 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s4 = "eturn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(" ascii
    $s5 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}