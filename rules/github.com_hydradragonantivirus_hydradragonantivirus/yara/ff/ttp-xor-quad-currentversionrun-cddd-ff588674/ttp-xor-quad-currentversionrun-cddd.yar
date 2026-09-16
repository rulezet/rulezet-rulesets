rule TTP_XOR_QUAD_CurrentVersionRun_cddd {
  strings:
    $key_cddd = { 9e b2 [2] ba bc [2] 91 90 [2] bf b2 [2] ab a9 [2] a4 b3 [2] ba ae [2] b8 af [2] a3 a9 [2] bf ae [2] a3 81 }

  condition:
    any of them
}