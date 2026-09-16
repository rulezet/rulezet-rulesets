rule TTP_XOR_MULT_DOSStub_dbdf {
  strings:
    $key_dbdf = { 8f b7 [2] fb af [2] bc ad [2] fb bc [2] b5 b0 [2] b9 ba [2] ae b1 [2] b5 ff [2] 88 }

  condition:
    any of them
}