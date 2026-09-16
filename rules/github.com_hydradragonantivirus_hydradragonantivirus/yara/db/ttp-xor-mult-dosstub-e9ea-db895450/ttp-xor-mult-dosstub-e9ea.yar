rule TTP_XOR_MULT_DOSStub_e9ea {
  strings:
    $key_e9ea = { bd 82 [2] c9 9a [2] 8e 98 [2] c9 89 [2] 87 85 [2] 8b 8f [2] 9c 84 [2] 87 ca [2] ba }

  condition:
    any of them
}