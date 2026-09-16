rule TTP_XOR_MULT_DOSStub_e80a {
  strings:
    $key_e80a = { bc 62 [2] c8 7a [2] 8f 78 [2] c8 69 [2] 86 65 [2] 8a 6f [2] 9d 64 [2] 86 2a [2] bb }

  condition:
    any of them
}