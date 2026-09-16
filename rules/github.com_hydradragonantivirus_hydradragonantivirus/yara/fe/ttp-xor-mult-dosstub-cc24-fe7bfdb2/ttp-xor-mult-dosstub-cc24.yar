rule TTP_XOR_MULT_DOSStub_cc24 {
  strings:
    $key_cc24 = { 98 4c [2] ec 54 [2] ab 56 [2] ec 47 [2] a2 4b [2] ae 41 [2] b9 4a [2] a2 04 [2] 9f }

  condition:
    any of them
}