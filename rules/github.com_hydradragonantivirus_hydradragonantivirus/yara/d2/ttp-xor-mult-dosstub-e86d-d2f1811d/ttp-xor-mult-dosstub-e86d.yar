rule TTP_XOR_MULT_DOSStub_e86d {
  strings:
    $key_e86d = { bc 05 [2] c8 1d [2] 8f 1f [2] c8 0e [2] 86 02 [2] 8a 08 [2] 9d 03 [2] 86 4d [2] bb }

  condition:
    any of them
}