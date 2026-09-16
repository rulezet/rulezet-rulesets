rule TTP_XOR_QUAD_CurrentVersionRun_7a13 {
  strings:
    $key_7a13 = { 29 7c [2] 0d 72 [2] 26 5e [2] 08 7c [2] 1c 67 [2] 13 7d [2] 0d 60 [2] 0f 61 [2] 14 67 [2] 08 60 [2] 14 4f }

  condition:
    any of them
}