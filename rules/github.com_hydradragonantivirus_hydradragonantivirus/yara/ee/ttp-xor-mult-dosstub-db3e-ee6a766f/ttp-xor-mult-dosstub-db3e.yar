rule TTP_XOR_MULT_DOSStub_db3e {
  strings:
    $key_db3e = { 8f 56 [2] fb 4e [2] bc 4c [2] fb 5d [2] b5 51 [2] b9 5b [2] ae 50 [2] b5 1e [2] 88 }

  condition:
    any of them
}