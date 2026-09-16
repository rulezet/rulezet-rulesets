rule TTP_XOR_MULT_DOSStub_cc2c {
  strings:
    $key_cc2c = { 98 44 [2] ec 5c [2] ab 5e [2] ec 4f [2] a2 43 [2] ae 49 [2] b9 42 [2] a2 0c [2] 9f }

  condition:
    any of them
}