rule TTP_XOR_MULT_DOSStub_d439 {
  strings:
    $key_d439 = { 80 51 [2] f4 49 [2] b3 4b [2] f4 5a [2] ba 56 [2] b6 5c [2] a1 57 [2] ba 19 [2] 87 }

  condition:
    any of them
}