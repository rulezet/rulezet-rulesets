rule TTP_XOR_MULT_DOSStub_e869 {
  strings:
    $key_e869 = { bc 01 [2] c8 19 [2] 8f 1b [2] c8 0a [2] 86 06 [2] 8a 0c [2] 9d 07 [2] 86 49 [2] bb }

  condition:
    any of them
}