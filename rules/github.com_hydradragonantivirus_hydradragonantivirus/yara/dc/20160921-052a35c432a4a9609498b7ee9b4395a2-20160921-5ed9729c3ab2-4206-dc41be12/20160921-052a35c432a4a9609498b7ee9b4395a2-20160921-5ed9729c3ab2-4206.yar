rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_5ed9729c3ab2_4206 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash3       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"
    hash4       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash5       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1 = "n \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s2 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\"" ascii
    $s3 = "n \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";}" ascii
    $s5 = " fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"O" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}