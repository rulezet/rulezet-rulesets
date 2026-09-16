rule TTP_XOR_QUAD_CurrentVersionRun_ed33 {
  strings:
    $key_ed33 = { be 5c [2] 9a 52 [2] b1 7e [2] 9f 5c [2] 8b 47 [2] 84 5d [2] 9a 40 [2] 98 41 [2] 83 47 [2] 9f 40 [2] 83 6f }

  condition:
    any of them
}