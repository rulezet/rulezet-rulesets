rule TTP_XOR_MULT_DOSStub_dbe2 {
  strings:
    $key_dbe2 = { 8f 8a [2] fb 92 [2] bc 90 [2] fb 81 [2] b5 8d [2] b9 87 [2] ae 8c [2] b5 c2 [2] 88 }

  condition:
    any of them
}