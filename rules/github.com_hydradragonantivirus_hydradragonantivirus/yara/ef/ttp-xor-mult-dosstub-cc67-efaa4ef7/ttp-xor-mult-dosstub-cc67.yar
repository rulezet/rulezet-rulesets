rule TTP_XOR_MULT_DOSStub_cc67 {
  strings:
    $key_cc67 = { 98 0f [2] ec 17 [2] ab 15 [2] ec 04 [2] a2 08 [2] ae 02 [2] b9 09 [2] a2 47 [2] 9f }

  condition:
    any of them
}