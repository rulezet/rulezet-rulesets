rule TTP_XOR_MULT_DOSStub_efea {
  strings:
    $key_efea = { bb 82 [2] cf 9a [2] 88 98 [2] cf 89 [2] 81 85 [2] 8d 8f [2] 9a 84 [2] 81 ca [2] bc }

  condition:
    any of them
}