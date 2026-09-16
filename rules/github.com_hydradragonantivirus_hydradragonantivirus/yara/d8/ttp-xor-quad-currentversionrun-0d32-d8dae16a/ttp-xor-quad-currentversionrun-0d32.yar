rule TTP_XOR_QUAD_CurrentVersionRun_0d32 {
  strings:
    $key_0d32 = { 5e 5d [2] 7a 53 [2] 51 7f [2] 7f 5d [2] 6b 46 [2] 64 5c [2] 7a 41 [2] 78 40 [2] 63 46 [2] 7f 41 [2] 63 6e }

  condition:
    any of them
}