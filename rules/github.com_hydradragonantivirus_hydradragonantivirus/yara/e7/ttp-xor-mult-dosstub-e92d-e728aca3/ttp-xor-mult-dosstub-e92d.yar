rule TTP_XOR_MULT_DOSStub_e92d {
  strings:
    $key_e92d = { bd 45 [2] c9 5d [2] 8e 5f [2] c9 4e [2] 87 42 [2] 8b 48 [2] 9c 43 [2] 87 0d [2] ba }

  condition:
    any of them
}