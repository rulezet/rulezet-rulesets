rule TTP_XOR_MULT_DOSStub_e823 {
  strings:
    $key_e823 = { bc 4b [2] c8 53 [2] 8f 51 [2] c8 40 [2] 86 4c [2] 8a 46 [2] 9d 4d [2] 86 03 [2] bb }

  condition:
    any of them
}