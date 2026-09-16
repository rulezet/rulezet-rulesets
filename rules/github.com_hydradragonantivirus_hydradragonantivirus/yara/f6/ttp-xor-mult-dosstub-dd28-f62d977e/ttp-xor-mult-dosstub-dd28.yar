rule TTP_XOR_MULT_DOSStub_dd28 {
  strings:
    $key_dd28 = { 89 40 [2] fd 58 [2] ba 5a [2] fd 4b [2] b3 47 [2] bf 4d [2] a8 46 [2] b3 08 [2] 8e }

  condition:
    any of them
}