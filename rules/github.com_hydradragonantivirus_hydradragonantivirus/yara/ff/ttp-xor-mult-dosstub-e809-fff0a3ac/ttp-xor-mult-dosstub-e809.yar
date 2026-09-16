rule TTP_XOR_MULT_DOSStub_e809 {
  strings:
    $key_e809 = { bc 61 [2] c8 79 [2] 8f 7b [2] c8 6a [2] 86 66 [2] 8a 6c [2] 9d 67 [2] 86 29 [2] bb }

  condition:
    any of them
}