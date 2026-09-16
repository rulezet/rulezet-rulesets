rule TTP_XOR_MULT_DOSStub_eeea {
  strings:
    $key_eeea = { ba 82 [2] ce 9a [2] 89 98 [2] ce 89 [2] 80 85 [2] 8c 8f [2] 9b 84 [2] 80 ca [2] bd }

  condition:
    any of them
}