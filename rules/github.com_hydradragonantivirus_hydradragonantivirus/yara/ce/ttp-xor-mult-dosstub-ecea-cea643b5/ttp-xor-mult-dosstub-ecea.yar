rule TTP_XOR_MULT_DOSStub_ecea {
  strings:
    $key_ecea = { b8 82 [2] cc 9a [2] 8b 98 [2] cc 89 [2] 82 85 [2] 8e 8f [2] 99 84 [2] 82 ca [2] bf }

  condition:
    any of them
}