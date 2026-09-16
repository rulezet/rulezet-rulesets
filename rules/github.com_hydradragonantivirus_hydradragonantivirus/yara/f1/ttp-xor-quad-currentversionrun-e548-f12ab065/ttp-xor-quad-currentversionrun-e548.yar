rule TTP_XOR_QUAD_CurrentVersionRun_e548 {
  strings:
    $key_e548 = { b6 27 [2] 92 29 [2] b9 05 [2] 97 27 [2] 83 3c [2] 8c 26 [2] 92 3b [2] 90 3a [2] 8b 3c [2] 97 3b [2] 8b 14 }

  condition:
    any of them
}