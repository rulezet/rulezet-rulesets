rule TTP_XOR_QUAD_CurrentVersionRun_ed1d {
  strings:
    $key_ed1d = { be 72 [2] 9a 7c [2] b1 50 [2] 9f 72 [2] 8b 69 [2] 84 73 [2] 9a 6e [2] 98 6f [2] 83 69 [2] 9f 6e [2] 83 41 }

  condition:
    any of them
}