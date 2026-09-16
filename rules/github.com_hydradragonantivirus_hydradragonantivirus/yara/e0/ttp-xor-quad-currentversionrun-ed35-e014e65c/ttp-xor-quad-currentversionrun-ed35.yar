rule TTP_XOR_QUAD_CurrentVersionRun_ed35 {
  strings:
    $key_ed35 = { be 5a [2] 9a 54 [2] b1 78 [2] 9f 5a [2] 8b 41 [2] 84 5b [2] 9a 46 [2] 98 47 [2] 83 41 [2] 9f 46 [2] 83 69 }

  condition:
    any of them
}