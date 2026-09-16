rule TTP_XOR_MULT_DOSStub_0813 {
  strings:
    $key_0813 = { 5c 7b [2] 28 63 [2] 6f 61 [2] 28 70 [2] 66 7c [2] 6a 76 [2] 7d 7d [2] 66 33 [2] 5b }

  condition:
    any of them
}