rule TTP_XOR_QUAD_CurrentVersionRun_1278 {
  strings:
    $key_1278 = { 41 17 [2] 65 19 [2] 4e 35 [2] 60 17 [2] 74 0c [2] 7b 16 [2] 65 0b [2] 67 0a [2] 7c 0c [2] 60 0b [2] 7c 24 }

  condition:
    any of them
}