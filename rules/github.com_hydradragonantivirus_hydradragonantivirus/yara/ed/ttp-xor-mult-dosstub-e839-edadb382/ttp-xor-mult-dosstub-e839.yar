rule TTP_XOR_MULT_DOSStub_e839 {
  strings:
    $key_e839 = { bc 51 [2] c8 49 [2] 8f 4b [2] c8 5a [2] 86 56 [2] 8a 5c [2] 9d 57 [2] 86 19 [2] bb }

  condition:
    any of them
}