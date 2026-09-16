rule TTP_XOR_MULT_DOSStub_c267 {
  strings:
    $key_c267 = { 96 0f [2] e2 17 [2] a5 15 [2] e2 04 [2] ac 08 [2] a0 02 [2] b7 09 [2] ac 47 [2] 91 }

  condition:
    any of them
}