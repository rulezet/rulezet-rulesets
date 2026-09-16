rule TTP_XOR_MULT_DOSStub_dd04 {
  strings:
    $key_dd04 = { 89 6c [2] fd 74 [2] ba 76 [2] fd 67 [2] b3 6b [2] bf 61 [2] a8 6a [2] b3 24 [2] 8e }

  condition:
    any of them
}