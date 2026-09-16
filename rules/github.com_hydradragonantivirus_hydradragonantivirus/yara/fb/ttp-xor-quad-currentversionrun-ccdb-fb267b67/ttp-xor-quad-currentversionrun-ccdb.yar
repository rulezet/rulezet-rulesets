rule TTP_XOR_QUAD_CurrentVersionRun_ccdb {
  strings:
    $key_ccdb = { 9f b4 [2] bb ba [2] 90 96 [2] be b4 [2] aa af [2] a5 b5 [2] bb a8 [2] b9 a9 [2] a2 af [2] be a8 [2] a2 87 }

  condition:
    any of them
}