rule TTP_XOR_MULT_DOSStub_e916 {
  strings:
    $key_e916 = { bd 7e [2] c9 66 [2] 8e 64 [2] c9 75 [2] 87 79 [2] 8b 73 [2] 9c 78 [2] 87 36 [2] ba }

  condition:
    any of them
}