rule TTP_XOR_QUAD_CurrentVersionRun_acf0 {
  strings:
    $key_acf0 = { ff 9f [2] db 91 [2] f0 bd [2] de 9f [2] ca 84 [2] c5 9e [2] db 83 [2] d9 82 [2] c2 84 [2] de 83 [2] c2 ac }

  condition:
    any of them
}