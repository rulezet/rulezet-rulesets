rule TTP_XOR_MULT_DOSStub_db7e {
  strings:
    $key_db7e = { 8f 16 [2] fb 0e [2] bc 0c [2] fb 1d [2] b5 11 [2] b9 1b [2] ae 10 [2] b5 5e [2] 88 }

  condition:
    any of them
}