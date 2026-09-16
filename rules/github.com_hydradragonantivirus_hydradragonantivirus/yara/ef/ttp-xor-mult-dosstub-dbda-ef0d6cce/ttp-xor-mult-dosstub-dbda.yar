rule TTP_XOR_MULT_DOSStub_dbda {
  strings:
    $key_dbda = { 8f b2 [2] fb aa [2] bc a8 [2] fb b9 [2] b5 b5 [2] b9 bf [2] ae b4 [2] b5 fa [2] 88 }

  condition:
    any of them
}