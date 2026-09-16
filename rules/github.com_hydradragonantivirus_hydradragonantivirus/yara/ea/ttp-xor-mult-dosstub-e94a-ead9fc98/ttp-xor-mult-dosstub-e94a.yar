rule TTP_XOR_MULT_DOSStub_e94a {
  strings:
    $key_e94a = { bd 22 [2] c9 3a [2] 8e 38 [2] c9 29 [2] 87 25 [2] 8b 2f [2] 9c 24 [2] 87 6a [2] ba }

  condition:
    any of them
}