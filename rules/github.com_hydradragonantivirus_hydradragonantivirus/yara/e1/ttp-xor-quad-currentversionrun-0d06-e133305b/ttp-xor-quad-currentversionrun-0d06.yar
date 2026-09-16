rule TTP_XOR_QUAD_CurrentVersionRun_0d06 {
  strings:
    $key_0d06 = { 5e 69 [2] 7a 67 [2] 51 4b [2] 7f 69 [2] 6b 72 [2] 64 68 [2] 7a 75 [2] 78 74 [2] 63 72 [2] 7f 75 [2] 63 5a }

  condition:
    any of them
}