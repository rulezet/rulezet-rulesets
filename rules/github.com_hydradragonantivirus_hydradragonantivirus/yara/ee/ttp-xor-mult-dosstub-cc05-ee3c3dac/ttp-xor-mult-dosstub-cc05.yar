rule TTP_XOR_MULT_DOSStub_cc05 {
  strings:
    $key_cc05 = { 98 6d [2] ec 75 [2] ab 77 [2] ec 66 [2] a2 6a [2] ae 60 [2] b9 6b [2] a2 25 [2] 9f }

  condition:
    any of them
}