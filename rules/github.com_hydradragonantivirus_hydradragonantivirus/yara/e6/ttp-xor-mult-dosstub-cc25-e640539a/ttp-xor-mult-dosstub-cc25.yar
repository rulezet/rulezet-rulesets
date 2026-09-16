rule TTP_XOR_MULT_DOSStub_cc25 {
  strings:
    $key_cc25 = { 98 4d [2] ec 55 [2] ab 57 [2] ec 46 [2] a2 4a [2] ae 40 [2] b9 4b [2] a2 05 [2] 9f }

  condition:
    any of them
}