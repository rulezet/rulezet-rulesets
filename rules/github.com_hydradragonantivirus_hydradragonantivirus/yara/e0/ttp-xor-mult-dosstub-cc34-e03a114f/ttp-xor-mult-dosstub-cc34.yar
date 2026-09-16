rule TTP_XOR_MULT_DOSStub_cc34 {
  strings:
    $key_cc34 = { 98 5c [2] ec 44 [2] ab 46 [2] ec 57 [2] a2 5b [2] ae 51 [2] b9 5a [2] a2 14 [2] 9f }

  condition:
    any of them
}