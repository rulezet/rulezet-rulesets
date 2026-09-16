rule TTP_XOR_MULT_DOSStub_e8f2 {
  strings:
    $key_e8f2 = { bc 9a [2] c8 82 [2] 8f 80 [2] c8 91 [2] 86 9d [2] 8a 97 [2] 9d 9c [2] 86 d2 [2] bb }

  condition:
    any of them
}