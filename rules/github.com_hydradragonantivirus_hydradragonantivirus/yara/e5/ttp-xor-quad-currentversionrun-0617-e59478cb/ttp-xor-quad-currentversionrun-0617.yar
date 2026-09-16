rule TTP_XOR_QUAD_CurrentVersionRun_0617 {
  strings:
    $key_0617 = { 55 78 [2] 71 76 [2] 5a 5a [2] 74 78 [2] 60 63 [2] 6f 79 [2] 71 64 [2] 73 65 [2] 68 63 [2] 74 64 [2] 68 4b }

  condition:
    any of them
}