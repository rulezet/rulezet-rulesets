rule TTP_XOR_MULT_DOSStub_dbdc {
  strings:
    $key_dbdc = { 8f b4 [2] fb ac [2] bc ae [2] fb bf [2] b5 b3 [2] b9 b9 [2] ae b2 [2] b5 fc [2] 88 }

  condition:
    any of them
}