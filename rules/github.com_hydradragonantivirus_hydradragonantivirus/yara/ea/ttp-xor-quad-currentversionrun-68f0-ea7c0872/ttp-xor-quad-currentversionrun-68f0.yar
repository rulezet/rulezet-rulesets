rule TTP_XOR_QUAD_CurrentVersionRun_68f0 {
  strings:
    $key_68f0 = { 3b 9f [2] 1f 91 [2] 34 bd [2] 1a 9f [2] 0e 84 [2] 01 9e [2] 1f 83 [2] 1d 82 [2] 06 84 [2] 1a 83 [2] 06 ac }

  condition:
    any of them
}