rule TTP_XOR_QUAD_CurrentVersionRun_ace1 {
  strings:
    $key_ace1 = { ff 8e [2] db 80 [2] f0 ac [2] de 8e [2] ca 95 [2] c5 8f [2] db 92 [2] d9 93 [2] c2 95 [2] de 92 [2] c2 bd }

  condition:
    any of them
}