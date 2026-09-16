rule TTP_XOR_MULT_DOSStub_d40e {
  strings:
    $key_d40e = { 80 66 [2] f4 7e [2] b3 7c [2] f4 6d [2] ba 61 [2] b6 6b [2] a1 60 [2] ba 2e [2] 87 }

  condition:
    any of them
}