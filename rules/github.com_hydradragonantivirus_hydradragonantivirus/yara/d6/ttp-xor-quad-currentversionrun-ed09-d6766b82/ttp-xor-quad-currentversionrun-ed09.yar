rule TTP_XOR_QUAD_CurrentVersionRun_ed09 {
  strings:
    $key_ed09 = { be 66 [2] 9a 68 [2] b1 44 [2] 9f 66 [2] 8b 7d [2] 84 67 [2] 9a 7a [2] 98 7b [2] 83 7d [2] 9f 7a [2] 83 55 }

  condition:
    any of them
}