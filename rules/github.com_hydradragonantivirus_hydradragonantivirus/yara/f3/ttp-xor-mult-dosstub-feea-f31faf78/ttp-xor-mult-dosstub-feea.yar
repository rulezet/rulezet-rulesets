rule TTP_XOR_MULT_DOSStub_feea {
  strings:
    $key_feea = { aa 82 [2] de 9a [2] 99 98 [2] de 89 [2] 90 85 [2] 9c 8f [2] 8b 84 [2] 90 ca [2] ad }

  condition:
    any of them
}