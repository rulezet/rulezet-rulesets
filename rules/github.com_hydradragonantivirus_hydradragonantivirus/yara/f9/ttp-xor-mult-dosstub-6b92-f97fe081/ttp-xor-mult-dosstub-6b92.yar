rule TTP_XOR_MULT_DOSStub_6b92 {
  strings:
    $key_6b92 = { 3f fa [2] 4b e2 [2] 0c e0 [2] 4b f1 [2] 05 fd [2] 09 f7 [2] 1e fc [2] 05 b2 [2] 38 }

  condition:
    any of them
}