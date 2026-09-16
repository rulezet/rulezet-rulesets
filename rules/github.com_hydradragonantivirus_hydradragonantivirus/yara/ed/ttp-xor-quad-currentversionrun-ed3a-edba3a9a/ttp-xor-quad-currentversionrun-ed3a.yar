rule TTP_XOR_QUAD_CurrentVersionRun_ed3a {
  strings:
    $key_ed3a = { be 55 [2] 9a 5b [2] b1 77 [2] 9f 55 [2] 8b 4e [2] 84 54 [2] 9a 49 [2] 98 48 [2] 83 4e [2] 9f 49 [2] 83 66 }

  condition:
    any of them
}