rule TTP_XOR_MULT_DOSStub_e82d {
  strings:
    $key_e82d = { bc 45 [2] c8 5d [2] 8f 5f [2] c8 4e [2] 86 42 [2] 8a 48 [2] 9d 43 [2] 86 0d [2] bb }

  condition:
    any of them
}