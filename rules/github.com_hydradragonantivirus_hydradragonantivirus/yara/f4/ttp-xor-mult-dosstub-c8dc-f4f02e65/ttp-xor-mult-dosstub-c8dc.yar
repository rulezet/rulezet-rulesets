rule TTP_XOR_MULT_DOSStub_c8dc {
  strings:
    $key_c8dc = { 9c b4 [2] e8 ac [2] af ae [2] e8 bf [2] a6 b3 [2] aa b9 [2] bd b2 [2] a6 fc [2] 9b }

  condition:
    any of them
}