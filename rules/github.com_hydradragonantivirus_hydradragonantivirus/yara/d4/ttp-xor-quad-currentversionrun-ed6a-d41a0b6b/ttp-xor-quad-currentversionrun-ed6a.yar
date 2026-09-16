rule TTP_XOR_QUAD_CurrentVersionRun_ed6a {
  strings:
    $key_ed6a = { be 05 [2] 9a 0b [2] b1 27 [2] 9f 05 [2] 8b 1e [2] 84 04 [2] 9a 19 [2] 98 18 [2] 83 1e [2] 9f 19 [2] 83 36 }

  condition:
    any of them
}