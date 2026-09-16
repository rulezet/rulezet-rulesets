rule TTP_XOR_QUAD_CurrentVersionRun_06f1 {
  strings:
    $key_06f1 = { 55 9e [2] 71 90 [2] 5a bc [2] 74 9e [2] 60 85 [2] 6f 9f [2] 71 82 [2] 73 83 [2] 68 85 [2] 74 82 [2] 68 ad }

  condition:
    any of them
}