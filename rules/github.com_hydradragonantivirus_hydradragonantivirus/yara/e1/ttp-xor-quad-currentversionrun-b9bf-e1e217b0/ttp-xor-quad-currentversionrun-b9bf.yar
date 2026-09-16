rule TTP_XOR_QUAD_CurrentVersionRun_b9bf {
  strings:
    $key_b9bf = { ea d0 [2] ce de [2] e5 f2 [2] cb d0 [2] df cb [2] d0 d1 [2] ce cc [2] cc cd [2] d7 cb [2] cb cc [2] d7 e3 }

  condition:
    any of them
}