rule TTP_XOR_MULT_DOSStub_e269 {
  strings:
    $key_e269 = { b6 01 [2] c2 19 [2] 85 1b [2] c2 0a [2] 8c 06 [2] 80 0c [2] 97 07 [2] 8c 49 [2] b1 }

  condition:
    any of them
}