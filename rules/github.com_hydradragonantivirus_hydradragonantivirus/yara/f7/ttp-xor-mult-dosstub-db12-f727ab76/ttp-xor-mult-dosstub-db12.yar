rule TTP_XOR_MULT_DOSStub_db12 {
  strings:
    $key_db12 = { 8f 7a [2] fb 62 [2] bc 60 [2] fb 71 [2] b5 7d [2] b9 77 [2] ae 7c [2] b5 32 [2] 88 }

  condition:
    any of them
}