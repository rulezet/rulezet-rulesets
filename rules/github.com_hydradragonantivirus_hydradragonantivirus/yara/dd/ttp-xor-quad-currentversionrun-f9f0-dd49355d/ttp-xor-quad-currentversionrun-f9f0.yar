rule TTP_XOR_QUAD_CurrentVersionRun_f9f0 {
  strings:
    $key_f9f0 = { aa 9f [2] 8e 91 [2] a5 bd [2] 8b 9f [2] 9f 84 [2] 90 9e [2] 8e 83 [2] 8c 82 [2] 97 84 [2] 8b 83 [2] 97 ac }

  condition:
    any of them
}