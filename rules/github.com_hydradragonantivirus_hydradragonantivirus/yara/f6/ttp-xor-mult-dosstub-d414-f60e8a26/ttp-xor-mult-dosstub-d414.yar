rule TTP_XOR_MULT_DOSStub_d414 {
  strings:
    $key_d414 = { 80 7c [2] f4 64 [2] b3 66 [2] f4 77 [2] ba 7b [2] b6 71 [2] a1 7a [2] ba 34 [2] 87 }

  condition:
    any of them
}