rule TTP_XOR_MULT_DOSStub_e912 {
  strings:
    $key_e912 = { bd 7a [2] c9 62 [2] 8e 60 [2] c9 71 [2] 87 7d [2] 8b 77 [2] 9c 7c [2] 87 32 [2] ba }

  condition:
    any of them
}