rule TTP_XOR_MULT_DOSStub_cc28 {
  strings:
    $key_cc28 = { 98 40 [2] ec 58 [2] ab 5a [2] ec 4b [2] a2 47 [2] ae 4d [2] b9 46 [2] a2 08 [2] 9f }

  condition:
    any of them
}