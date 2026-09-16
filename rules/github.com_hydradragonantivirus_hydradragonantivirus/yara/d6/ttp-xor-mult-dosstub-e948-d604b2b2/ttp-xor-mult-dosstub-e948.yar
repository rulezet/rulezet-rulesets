rule TTP_XOR_MULT_DOSStub_e948 {
  strings:
    $key_e948 = { bd 20 [2] c9 38 [2] 8e 3a [2] c9 2b [2] 87 27 [2] 8b 2d [2] 9c 26 [2] 87 68 [2] ba }

  condition:
    any of them
}