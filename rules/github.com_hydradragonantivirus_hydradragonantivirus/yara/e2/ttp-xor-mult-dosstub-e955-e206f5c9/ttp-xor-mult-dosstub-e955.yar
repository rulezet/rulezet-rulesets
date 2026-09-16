rule TTP_XOR_MULT_DOSStub_e955 {
  strings:
    $key_e955 = { bd 3d [2] c9 25 [2] 8e 27 [2] c9 36 [2] 87 3a [2] 8b 30 [2] 9c 3b [2] 87 75 [2] ba }

  condition:
    any of them
}