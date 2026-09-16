rule TTP_XOR_MULT_DOSStub_e825 {
  strings:
    $key_e825 = { bc 4d [2] c8 55 [2] 8f 57 [2] c8 46 [2] 86 4a [2] 8a 40 [2] 9d 4b [2] 86 05 [2] bb }

  condition:
    any of them
}