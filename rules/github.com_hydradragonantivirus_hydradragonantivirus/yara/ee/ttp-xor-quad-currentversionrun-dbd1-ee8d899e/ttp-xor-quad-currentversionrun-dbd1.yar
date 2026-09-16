rule TTP_XOR_QUAD_CurrentVersionRun_dbd1 {
  strings:
    $key_dbd1 = { 88 be [2] ac b0 [2] 87 9c [2] a9 be [2] bd a5 [2] b2 bf [2] ac a2 [2] ae a3 [2] b5 a5 [2] a9 a2 [2] b5 8d }

  condition:
    any of them
}