rule TTP_XOR_QUAD_CurrentVersionRun_1978 {
  strings:
    $key_1978 = { 4a 17 [2] 6e 19 [2] 45 35 [2] 6b 17 [2] 7f 0c [2] 70 16 [2] 6e 0b [2] 6c 0a [2] 77 0c [2] 6b 0b [2] 77 24 }

  condition:
    any of them
}