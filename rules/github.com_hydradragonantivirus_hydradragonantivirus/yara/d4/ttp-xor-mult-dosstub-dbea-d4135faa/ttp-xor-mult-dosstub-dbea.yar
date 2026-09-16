rule TTP_XOR_MULT_DOSStub_dbea {
  strings:
    $key_dbea = { 8f 82 [2] fb 9a [2] bc 98 [2] fb 89 [2] b5 85 [2] b9 8f [2] ae 84 [2] b5 ca [2] 88 }

  condition:
    any of them
}