rule TTP_XOR_QUAD_CurrentVersionRun_ed4c {
  strings:
    $key_ed4c = { be 23 [2] 9a 2d [2] b1 01 [2] 9f 23 [2] 8b 38 [2] 84 22 [2] 9a 3f [2] 98 3e [2] 83 38 [2] 9f 3f [2] 83 10 }

  condition:
    any of them
}