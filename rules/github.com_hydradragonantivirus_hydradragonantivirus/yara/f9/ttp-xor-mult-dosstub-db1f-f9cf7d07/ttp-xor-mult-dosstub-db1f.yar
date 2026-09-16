rule TTP_XOR_MULT_DOSStub_db1f {
  strings:
    $key_db1f = { 8f 77 [2] fb 6f [2] bc 6d [2] fb 7c [2] b5 70 [2] b9 7a [2] ae 71 [2] b5 3f [2] 88 }

  condition:
    any of them
}