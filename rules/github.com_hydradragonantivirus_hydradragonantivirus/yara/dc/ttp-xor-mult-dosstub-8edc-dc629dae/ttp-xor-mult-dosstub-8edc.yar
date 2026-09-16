rule TTP_XOR_MULT_DOSStub_8edc {
  strings:
    $key_8edc = { da b4 [2] ae ac [2] e9 ae [2] ae bf [2] e0 b3 [2] ec b9 [2] fb b2 [2] e0 fc [2] dd }

  condition:
    any of them
}