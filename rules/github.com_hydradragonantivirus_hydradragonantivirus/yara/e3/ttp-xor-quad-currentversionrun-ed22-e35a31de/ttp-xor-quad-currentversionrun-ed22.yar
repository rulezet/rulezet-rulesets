rule TTP_XOR_QUAD_CurrentVersionRun_ed22 {
  strings:
    $key_ed22 = { be 4d [2] 9a 43 [2] b1 6f [2] 9f 4d [2] 8b 56 [2] 84 4c [2] 9a 51 [2] 98 50 [2] 83 56 [2] 9f 51 [2] 83 7e }

  condition:
    any of them
}