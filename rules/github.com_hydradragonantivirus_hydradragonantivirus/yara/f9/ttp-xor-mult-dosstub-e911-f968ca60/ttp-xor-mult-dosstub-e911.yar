rule TTP_XOR_MULT_DOSStub_e911 {
  strings:
    $key_e911 = { bd 79 [2] c9 61 [2] 8e 63 [2] c9 72 [2] 87 7e [2] 8b 74 [2] 9c 7f [2] 87 31 [2] ba }

  condition:
    any of them
}