rule TTP_XOR_MULT_DOSStub_e976 {
  strings:
    $key_e976 = { bd 1e [2] c9 06 [2] 8e 04 [2] c9 15 [2] 87 19 [2] 8b 13 [2] 9c 18 [2] 87 56 [2] ba }

  condition:
    any of them
}