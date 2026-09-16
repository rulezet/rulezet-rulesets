rule TTP_XOR_MULT_DOSStub_e9f4 {
  strings:
    $key_e9f4 = { bd 9c [2] c9 84 [2] 8e 86 [2] c9 97 [2] 87 9b [2] 8b 91 [2] 9c 9a [2] 87 d4 [2] ba }

  condition:
    any of them
}