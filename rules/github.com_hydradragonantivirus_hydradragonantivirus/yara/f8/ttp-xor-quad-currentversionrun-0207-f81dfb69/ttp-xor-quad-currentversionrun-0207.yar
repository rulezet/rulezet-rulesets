rule TTP_XOR_QUAD_CurrentVersionRun_0207 {
  strings:
    $key_0207 = { 51 68 [2] 75 66 [2] 5e 4a [2] 70 68 [2] 64 73 [2] 6b 69 [2] 75 74 [2] 77 75 [2] 6c 73 [2] 70 74 [2] 6c 5b }

  condition:
    any of them
}