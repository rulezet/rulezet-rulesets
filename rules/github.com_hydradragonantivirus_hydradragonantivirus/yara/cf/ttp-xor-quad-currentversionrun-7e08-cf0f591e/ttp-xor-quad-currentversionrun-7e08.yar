rule TTP_XOR_QUAD_CurrentVersionRun_7e08 {
  strings:
    $key_7e08 = { 2d 67 [2] 09 69 [2] 22 45 [2] 0c 67 [2] 18 7c [2] 17 66 [2] 09 7b [2] 0b 7a [2] 10 7c [2] 0c 7b [2] 10 54 }

  condition:
    any of them
}