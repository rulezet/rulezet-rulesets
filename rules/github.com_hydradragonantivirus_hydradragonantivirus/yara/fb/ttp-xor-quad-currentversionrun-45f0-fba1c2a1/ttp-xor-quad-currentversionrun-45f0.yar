rule TTP_XOR_QUAD_CurrentVersionRun_45f0 {
  strings:
    $key_45f0 = { 16 9f [2] 32 91 [2] 19 bd [2] 37 9f [2] 23 84 [2] 2c 9e [2] 32 83 [2] 30 82 [2] 2b 84 [2] 37 83 [2] 2b ac }

  condition:
    any of them
}