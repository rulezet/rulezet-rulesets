rule TTP_XOR_MULT_DOSStub_dbfb {
  strings:
    $key_dbfb = { 8f 93 [2] fb 8b [2] bc 89 [2] fb 98 [2] b5 94 [2] b9 9e [2] ae 95 [2] b5 db [2] 88 }

  condition:
    any of them
}