rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_e2594cbf7523_4603 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash3       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash4       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = ",(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){" ascii
    $s2 = "urn \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s3 = "tion f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s4 = "f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s5 = "{return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"QDg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}