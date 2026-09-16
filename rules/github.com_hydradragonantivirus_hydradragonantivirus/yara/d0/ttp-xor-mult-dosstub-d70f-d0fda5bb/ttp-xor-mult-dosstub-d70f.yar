rule TTP_XOR_MULT_DOSStub_d70f {
  strings:
    $key_d70f = { 83 67 [2] f7 7f [2] b0 7d [2] f7 6c [2] b9 60 [2] b5 6a [2] a2 61 [2] b9 2f [2] 84 }

  condition:
    any of them
}