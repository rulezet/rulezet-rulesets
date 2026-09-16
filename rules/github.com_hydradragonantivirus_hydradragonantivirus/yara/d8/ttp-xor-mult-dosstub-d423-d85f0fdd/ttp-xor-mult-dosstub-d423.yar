rule TTP_XOR_MULT_DOSStub_d423 {
  strings:
    $key_d423 = { 80 4b [2] f4 53 [2] b3 51 [2] f4 40 [2] ba 4c [2] b6 46 [2] a1 4d [2] ba 03 [2] 87 }

  condition:
    any of them
}