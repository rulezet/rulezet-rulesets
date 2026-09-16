rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_99d82d332144_4451 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_99d82d33214407e421e255b85f02daae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"

  strings:
    $s1 = "(function f000(){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s2 = "on f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s3 = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000()" ascii
    $s4 = "rn \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(fu" ascii
    $s5 = "})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}