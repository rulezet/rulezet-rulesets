rule TTP_XOR_MULT_DOSStub_e968 {
  strings:
    $key_e968 = { bd 00 [2] c9 18 [2] 8e 1a [2] c9 0b [2] 87 07 [2] 8b 0d [2] 9c 06 [2] 87 48 [2] ba }

  condition:
    any of them
}