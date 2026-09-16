rule TTP_XOR_QUAD_CurrentVersionRun_78f0 {
  strings:
    $key_78f0 = { 2b 9f [2] 0f 91 [2] 24 bd [2] 0a 9f [2] 1e 84 [2] 11 9e [2] 0f 83 [2] 0d 82 [2] 16 84 [2] 0a 83 [2] 16 ac }

  condition:
    any of them
}