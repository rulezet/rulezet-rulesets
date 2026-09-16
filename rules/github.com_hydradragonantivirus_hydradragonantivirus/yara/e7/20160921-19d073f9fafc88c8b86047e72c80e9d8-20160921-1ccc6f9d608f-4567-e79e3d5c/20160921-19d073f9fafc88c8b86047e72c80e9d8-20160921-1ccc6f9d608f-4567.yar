rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_1ccc6f9d608f_4567 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash3       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash4       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash5       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = "tion f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s2 = "f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii
    $s3 = "DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(functi" ascii
    $s4 = "urn \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(f" ascii
    $s5 = "){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}