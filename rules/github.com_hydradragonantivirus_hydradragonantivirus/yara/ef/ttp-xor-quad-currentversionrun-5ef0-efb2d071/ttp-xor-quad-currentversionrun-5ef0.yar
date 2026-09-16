rule TTP_XOR_QUAD_CurrentVersionRun_5ef0 {
  strings:
    $key_5ef0 = { 0d 9f [2] 29 91 [2] 02 bd [2] 2c 9f [2] 38 84 [2] 37 9e [2] 29 83 [2] 2b 82 [2] 30 84 [2] 2c 83 [2] 30 ac }

  condition:
    any of them
}