rule TTP_XOR_MULT_DOSStub_e93e {
  strings:
    $key_e93e = { bd 56 [2] c9 4e [2] 8e 4c [2] c9 5d [2] 87 51 [2] 8b 5b [2] 9c 50 [2] 87 1e [2] ba }

  condition:
    any of them
}