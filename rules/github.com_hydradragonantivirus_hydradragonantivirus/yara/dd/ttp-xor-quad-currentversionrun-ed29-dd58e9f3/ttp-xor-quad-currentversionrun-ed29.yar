rule TTP_XOR_QUAD_CurrentVersionRun_ed29 {
  strings:
    $key_ed29 = { be 46 [2] 9a 48 [2] b1 64 [2] 9f 46 [2] 8b 5d [2] 84 47 [2] 9a 5a [2] 98 5b [2] 83 5d [2] 9f 5a [2] 83 75 }

  condition:
    any of them
}