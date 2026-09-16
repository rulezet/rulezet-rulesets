rule TTP_XOR_QUAD_CurrentVersionRun_fc32 {
  strings:
    $key_fc32 = { af 5d [2] 8b 53 [2] a0 7f [2] 8e 5d [2] 9a 46 [2] 95 5c [2] 8b 41 [2] 89 40 [2] 92 46 [2] 8e 41 [2] 92 6e }

  condition:
    any of them
}