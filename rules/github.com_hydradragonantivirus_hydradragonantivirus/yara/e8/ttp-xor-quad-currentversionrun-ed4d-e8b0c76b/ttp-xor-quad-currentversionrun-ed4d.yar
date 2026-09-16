rule TTP_XOR_QUAD_CurrentVersionRun_ed4d {
  strings:
    $key_ed4d = { be 22 [2] 9a 2c [2] b1 00 [2] 9f 22 [2] 8b 39 [2] 84 23 [2] 9a 3e [2] 98 3f [2] 83 39 [2] 9f 3e [2] 83 11 }

  condition:
    any of them
}