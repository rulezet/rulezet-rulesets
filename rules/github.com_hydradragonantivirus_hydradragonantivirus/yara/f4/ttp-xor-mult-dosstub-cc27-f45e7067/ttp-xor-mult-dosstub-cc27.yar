rule TTP_XOR_MULT_DOSStub_cc27 {
  strings:
    $key_cc27 = { 98 4f [2] ec 57 [2] ab 55 [2] ec 44 [2] a2 48 [2] ae 42 [2] b9 49 [2] a2 07 [2] 9f }

  condition:
    any of them
}