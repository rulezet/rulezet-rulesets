rule _20160921_6b34f0b83cb5d89ac574db511a389f02_20160921_9c9fcc818a70_5356 {
  meta:
    description = "datamaliciousorder - from files 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash2       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"

  strings:
    $s1 = "(function f000(){return \"YTp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s2 = "tion f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s3 = "GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s4 = "){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})" ascii
    $s5 = "turn \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"BMj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}