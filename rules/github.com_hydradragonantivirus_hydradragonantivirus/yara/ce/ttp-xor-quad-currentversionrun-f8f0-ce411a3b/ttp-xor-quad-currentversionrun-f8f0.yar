rule TTP_XOR_QUAD_CurrentVersionRun_f8f0 {
  strings:
    $key_f8f0 = { ab 9f [2] 8f 91 [2] a4 bd [2] 8a 9f [2] 9e 84 [2] 91 9e [2] 8f 83 [2] 8d 82 [2] 96 84 [2] 8a 83 [2] 96 ac }

  condition:
    any of them
}