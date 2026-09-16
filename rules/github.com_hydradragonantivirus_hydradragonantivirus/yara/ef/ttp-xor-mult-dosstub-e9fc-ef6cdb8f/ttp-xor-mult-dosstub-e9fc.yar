rule TTP_XOR_MULT_DOSStub_e9fc {
  strings:
    $key_e9fc = { bd 94 [2] c9 8c [2] 8e 8e [2] c9 9f [2] 87 93 [2] 8b 99 [2] 9c 92 [2] 87 dc [2] ba }

  condition:
    any of them
}