rule TTP_XOR_MULT_DOSStub_cc4a {
  strings:
    $key_cc4a = { 98 22 [2] ec 3a [2] ab 38 [2] ec 29 [2] a2 25 [2] ae 2f [2] b9 24 [2] a2 6a [2] 9f }

  condition:
    any of them
}