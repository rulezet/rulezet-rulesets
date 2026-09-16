rule TTP_XOR_QUAD_CurrentVersionRun_69f0 {
  strings:
    $key_69f0 = { 3a 9f [2] 1e 91 [2] 35 bd [2] 1b 9f [2] 0f 84 [2] 00 9e [2] 1e 83 [2] 1c 82 [2] 07 84 [2] 1b 83 [2] 07 ac }

  condition:
    any of them
}