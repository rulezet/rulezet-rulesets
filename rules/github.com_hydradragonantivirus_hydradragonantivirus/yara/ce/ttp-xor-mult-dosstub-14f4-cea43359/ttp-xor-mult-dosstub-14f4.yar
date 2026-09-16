rule TTP_XOR_MULT_DOSStub_14f4 {
  strings:
    $key_14f4 = { 40 9c [2] 34 84 [2] 73 86 [2] 34 97 [2] 7a 9b [2] 76 91 [2] 61 9a [2] 7a d4 [2] 47 }

  condition:
    any of them
}