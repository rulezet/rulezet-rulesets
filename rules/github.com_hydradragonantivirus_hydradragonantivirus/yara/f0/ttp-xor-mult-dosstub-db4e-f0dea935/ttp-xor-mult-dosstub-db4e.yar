rule TTP_XOR_MULT_DOSStub_db4e {
  strings:
    $key_db4e = { 8f 26 [2] fb 3e [2] bc 3c [2] fb 2d [2] b5 21 [2] b9 2b [2] ae 20 [2] b5 6e [2] 88 }

  condition:
    any of them
}