rule TTP_XOR_MULT_DOSStub_cc0c {
  strings:
    $key_cc0c = { 98 64 [2] ec 7c [2] ab 7e [2] ec 6f [2] a2 63 [2] ae 69 [2] b9 62 [2] a2 2c [2] 9f }

  condition:
    any of them
}