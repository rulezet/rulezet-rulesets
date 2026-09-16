rule TTP_XOR_MULT_DOSStub_e974 {
  strings:
    $key_e974 = { bd 1c [2] c9 04 [2] 8e 06 [2] c9 17 [2] 87 1b [2] 8b 11 [2] 9c 1a [2] 87 54 [2] ba }

  condition:
    any of them
}