rule TTP_XOR_MULT_DOSStub_e935 {
  strings:
    $key_e935 = { bd 5d [2] c9 45 [2] 8e 47 [2] c9 56 [2] 87 5a [2] 8b 50 [2] 9c 5b [2] 87 15 [2] ba }

  condition:
    any of them
}