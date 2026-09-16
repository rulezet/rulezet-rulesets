rule TTP_XOR_MULT_DOSStub_e469 {
  strings:
    $key_e469 = { b0 01 [2] c4 19 [2] 83 1b [2] c4 0a [2] 8a 06 [2] 86 0c [2] 91 07 [2] 8a 49 [2] b7 }

  condition:
    any of them
}