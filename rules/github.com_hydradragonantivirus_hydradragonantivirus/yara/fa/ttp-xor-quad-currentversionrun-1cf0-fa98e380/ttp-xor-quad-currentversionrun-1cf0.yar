rule TTP_XOR_QUAD_CurrentVersionRun_1cf0 {
  strings:
    $key_1cf0 = { 4f 9f [2] 6b 91 [2] 40 bd [2] 6e 9f [2] 7a 84 [2] 75 9e [2] 6b 83 [2] 69 82 [2] 72 84 [2] 6e 83 [2] 72 ac }

  condition:
    any of them
}