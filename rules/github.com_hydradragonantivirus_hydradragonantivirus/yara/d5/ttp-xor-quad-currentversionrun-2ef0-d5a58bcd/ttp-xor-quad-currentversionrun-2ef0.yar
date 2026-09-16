rule TTP_XOR_QUAD_CurrentVersionRun_2ef0 {
  strings:
    $key_2ef0 = { 7d 9f [2] 59 91 [2] 72 bd [2] 5c 9f [2] 48 84 [2] 47 9e [2] 59 83 [2] 5b 82 [2] 40 84 [2] 5c 83 [2] 40 ac }

  condition:
    any of them
}