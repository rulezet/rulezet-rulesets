rule TTP_XOR_MULT_DOSStub_d73a {
  strings:
    $key_d73a = { 83 52 [2] f7 4a [2] b0 48 [2] f7 59 [2] b9 55 [2] b5 5f [2] a2 54 [2] b9 1a [2] 84 }

  condition:
    any of them
}