rule TTP_XOR_MULT_DOSStub_e959 {
  strings:
    $key_e959 = { bd 31 [2] c9 29 [2] 8e 2b [2] c9 3a [2] 87 36 [2] 8b 3c [2] 9c 37 [2] 87 79 [2] ba }

  condition:
    any of them
}