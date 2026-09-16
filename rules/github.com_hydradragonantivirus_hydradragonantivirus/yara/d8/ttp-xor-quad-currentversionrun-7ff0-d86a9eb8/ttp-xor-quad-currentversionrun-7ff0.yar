rule TTP_XOR_QUAD_CurrentVersionRun_7ff0 {
  strings:
    $key_7ff0 = { 2c 9f [2] 08 91 [2] 23 bd [2] 0d 9f [2] 19 84 [2] 16 9e [2] 08 83 [2] 0a 82 [2] 11 84 [2] 0d 83 [2] 11 ac }

  condition:
    any of them
}