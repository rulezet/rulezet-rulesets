rule TTP_XOR_QUAD_CurrentVersionRun_ed72 {
  strings:
    $key_ed72 = { be 1d [2] 9a 13 [2] b1 3f [2] 9f 1d [2] 8b 06 [2] 84 1c [2] 9a 01 [2] 98 00 [2] 83 06 [2] 9f 01 [2] 83 2e }

  condition:
    any of them
}