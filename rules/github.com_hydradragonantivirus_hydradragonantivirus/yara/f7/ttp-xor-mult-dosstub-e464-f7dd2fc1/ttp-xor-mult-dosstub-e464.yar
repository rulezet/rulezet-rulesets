rule TTP_XOR_MULT_DOSStub_e464 {
  strings:
    $key_e464 = { b0 0c [2] c4 14 [2] 83 16 [2] c4 07 [2] 8a 0b [2] 86 01 [2] 91 0a [2] 8a 44 [2] b7 }

  condition:
    any of them
}