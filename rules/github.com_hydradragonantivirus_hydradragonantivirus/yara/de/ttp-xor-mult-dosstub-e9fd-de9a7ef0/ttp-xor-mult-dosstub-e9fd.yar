rule TTP_XOR_MULT_DOSStub_e9fd {
  strings:
    $key_e9fd = { bd 95 [2] c9 8d [2] 8e 8f [2] c9 9e [2] 87 92 [2] 8b 98 [2] 9c 93 [2] 87 dd [2] ba }

  condition:
    any of them
}