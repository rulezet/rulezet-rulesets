rule TTP_XOR_MULT_DOSStub_e9f8 {
  strings:
    $key_e9f8 = { bd 90 [2] c9 88 [2] 8e 8a [2] c9 9b [2] 87 97 [2] 8b 9d [2] 9c 96 [2] 87 d8 [2] ba }

  condition:
    any of them
}