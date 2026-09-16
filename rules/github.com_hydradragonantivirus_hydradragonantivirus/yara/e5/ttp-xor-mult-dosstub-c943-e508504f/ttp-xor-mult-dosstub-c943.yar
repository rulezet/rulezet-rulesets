rule TTP_XOR_MULT_DOSStub_c943 {
  strings:
    $key_c943 = { 9d 2b [2] e9 33 [2] ae 31 [2] e9 20 [2] a7 2c [2] ab 26 [2] bc 2d [2] a7 63 [2] 9a }

  condition:
    any of them
}