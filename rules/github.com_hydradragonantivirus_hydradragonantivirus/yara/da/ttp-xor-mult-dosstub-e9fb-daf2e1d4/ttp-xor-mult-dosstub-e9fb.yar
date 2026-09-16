rule TTP_XOR_MULT_DOSStub_e9fb {
  strings:
    $key_e9fb = { bd 93 [2] c9 8b [2] 8e 89 [2] c9 98 [2] 87 94 [2] 8b 9e [2] 9c 95 [2] 87 db [2] ba }

  condition:
    any of them
}