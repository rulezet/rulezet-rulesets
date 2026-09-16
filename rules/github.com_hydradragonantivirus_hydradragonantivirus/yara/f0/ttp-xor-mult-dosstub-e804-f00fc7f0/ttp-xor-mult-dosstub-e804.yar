rule TTP_XOR_MULT_DOSStub_e804 {
  strings:
    $key_e804 = { bc 6c [2] c8 74 [2] 8f 76 [2] c8 67 [2] 86 6b [2] 8a 61 [2] 9d 6a [2] 86 24 [2] bb }

  condition:
    any of them
}