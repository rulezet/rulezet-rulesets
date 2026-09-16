rule TTP_XOR_QUAD_CurrentVersionRun_edf8 {
  strings:
    $key_edf8 = { be 97 [2] 9a 99 [2] b1 b5 [2] 9f 97 [2] 8b 8c [2] 84 96 [2] 9a 8b [2] 98 8a [2] 83 8c [2] 9f 8b [2] 83 a4 }

  condition:
    any of them
}