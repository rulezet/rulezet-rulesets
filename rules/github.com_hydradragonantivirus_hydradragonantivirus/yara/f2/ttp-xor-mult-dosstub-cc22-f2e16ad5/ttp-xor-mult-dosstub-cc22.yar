rule TTP_XOR_MULT_DOSStub_cc22 {
  strings:
    $key_cc22 = { 98 4a [2] ec 52 [2] ab 50 [2] ec 41 [2] a2 4d [2] ae 47 [2] b9 4c [2] a2 02 [2] 9f }

  condition:
    any of them
}