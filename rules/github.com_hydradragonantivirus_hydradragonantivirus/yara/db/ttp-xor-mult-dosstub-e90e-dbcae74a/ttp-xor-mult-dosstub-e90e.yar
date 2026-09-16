rule TTP_XOR_MULT_DOSStub_e90e {
  strings:
    $key_e90e = { bd 66 [2] c9 7e [2] 8e 7c [2] c9 6d [2] 87 61 [2] 8b 6b [2] 9c 60 [2] 87 2e [2] ba }

  condition:
    any of them
}