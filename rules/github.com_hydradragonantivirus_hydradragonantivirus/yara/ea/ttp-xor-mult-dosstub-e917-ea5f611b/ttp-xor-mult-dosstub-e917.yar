rule TTP_XOR_MULT_DOSStub_e917 {
  strings:
    $key_e917 = { bd 7f [2] c9 67 [2] 8e 65 [2] c9 74 [2] 87 78 [2] 8b 72 [2] 9c 79 [2] 87 37 [2] ba }

  condition:
    any of them
}