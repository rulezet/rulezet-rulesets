rule TTP_XOR_MULT_DOSStub_d77a {
  strings:
    $key_d77a = { 83 12 [2] f7 0a [2] b0 08 [2] f7 19 [2] b9 15 [2] b5 1f [2] a2 14 [2] b9 5a [2] 84 }

  condition:
    any of them
}