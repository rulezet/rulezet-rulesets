rule TTP_XOR_MULT_DOSStub_66f4 {
  strings:
    $key_66f4 = { 32 9c [2] 46 84 [2] 01 86 [2] 46 97 [2] 08 9b [2] 04 91 [2] 13 9a [2] 08 d4 [2] 35 }

  condition:
    any of them
}