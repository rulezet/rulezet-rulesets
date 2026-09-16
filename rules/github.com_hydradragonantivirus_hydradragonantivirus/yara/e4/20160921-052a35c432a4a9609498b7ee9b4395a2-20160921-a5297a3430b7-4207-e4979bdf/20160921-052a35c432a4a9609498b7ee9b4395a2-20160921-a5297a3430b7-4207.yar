rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_a5297a3430b7_4207 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash3       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"

  strings:
    $s1 = "nction fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){ret" ascii
    $s2 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo\";})()," ascii
    $s3 = "k(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";" ascii
    $s4 = "n fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}