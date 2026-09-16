rule TTP_XOR_QUAD_CurrentVersionRun_bbdb {
  strings:
    $key_bbdb = { e8 b4 [2] cc ba [2] e7 96 [2] c9 b4 [2] dd af [2] d2 b5 [2] cc a8 [2] ce a9 [2] d5 af [2] c9 a8 [2] d5 87 }

  condition:
    any of them
}