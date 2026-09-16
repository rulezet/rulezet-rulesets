rule TTP_XOR_MULT_DOSStub_db08 {
  strings:
    $key_db08 = { 8f 60 [2] fb 78 [2] bc 7a [2] fb 6b [2] b5 67 [2] b9 6d [2] ae 66 [2] b5 28 [2] 88 }

  condition:
    any of them
}