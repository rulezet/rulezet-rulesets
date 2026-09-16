rule TTP_XOR_QUAD_CurrentVersionRun_2cf0 {
  strings:
    $key_2cf0 = { 7f 9f [2] 5b 91 [2] 70 bd [2] 5e 9f [2] 4a 84 [2] 45 9e [2] 5b 83 [2] 59 82 [2] 42 84 [2] 5e 83 [2] 42 ac }

  condition:
    any of them
}