rule TTP_XOR_MULT_DOSStub_6bad {
  strings:
    $key_6bad = { 3f c5 [2] 4b dd [2] 0c df [2] 4b ce [2] 05 c2 [2] 09 c8 [2] 1e c3 [2] 05 8d [2] 38 }

  condition:
    any of them
}