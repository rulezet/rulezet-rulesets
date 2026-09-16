rule TTP_XOR_MULT_DOSStub_e87d {
  strings:
    $key_e87d = { bc 15 [2] c8 0d [2] 8f 0f [2] c8 1e [2] 86 12 [2] 8a 18 [2] 9d 13 [2] 86 5d [2] bb }

  condition:
    any of them
}