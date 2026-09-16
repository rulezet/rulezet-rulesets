rule TTP_XOR_MULT_DOSStub_e834 {
  strings:
    $key_e834 = { bc 5c [2] c8 44 [2] 8f 46 [2] c8 57 [2] 86 5b [2] 8a 51 [2] 9d 5a [2] 86 14 [2] bb }

  condition:
    any of them
}