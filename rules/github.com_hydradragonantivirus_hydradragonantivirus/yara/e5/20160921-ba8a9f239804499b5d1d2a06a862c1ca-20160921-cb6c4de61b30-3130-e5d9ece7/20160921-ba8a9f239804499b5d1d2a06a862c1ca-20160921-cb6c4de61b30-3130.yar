rule _20160921_ba8a9f239804499b5d1d2a06a862c1ca_20160921_cb6c4de61b30_3130 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})" ascii
    $s2 = "f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZF" ascii
    $s3 = "){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s4 = "ion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s5 = "SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Ml\";})(),(functio" ascii
    $s6 = "tion f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return" ascii
    $s7 = "u\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}