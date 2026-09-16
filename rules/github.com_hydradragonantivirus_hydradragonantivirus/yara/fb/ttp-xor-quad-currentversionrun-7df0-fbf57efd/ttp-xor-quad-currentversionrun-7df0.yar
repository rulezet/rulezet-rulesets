rule TTP_XOR_QUAD_CurrentVersionRun_7df0 {
  strings:
    $key_7df0 = { 2e 9f [2] 0a 91 [2] 21 bd [2] 0f 9f [2] 1b 84 [2] 14 9e [2] 0a 83 [2] 08 82 [2] 13 84 [2] 0f 83 [2] 13 ac }

  condition:
    any of them
}