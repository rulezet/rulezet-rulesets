rule TTP_XOR_MULT_DOSStub_dd13 {
  strings:
    $key_dd13 = { 89 7b [2] fd 63 [2] ba 61 [2] fd 70 [2] b3 7c [2] bf 76 [2] a8 7d [2] b3 33 [2] 8e }

  condition:
    any of them
}