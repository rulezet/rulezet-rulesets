rule TTP_XOR_QUAD_CurrentVersionRun_1c01 {
  strings:
    $key_1c01 = { 4f 6e [2] 6b 60 [2] 40 4c [2] 6e 6e [2] 7a 75 [2] 75 6f [2] 6b 72 [2] 69 73 [2] 72 75 [2] 6e 72 [2] 72 5d }

  condition:
    any of them
}