rule TTP_XOR_MULT_DOSStub_efdf {
  strings:
    $key_efdf = { bb b7 [2] cf af [2] 88 ad [2] cf bc [2] 81 b0 [2] 8d ba [2] 9a b1 [2] 81 ff [2] bc }

  condition:
    any of them
}