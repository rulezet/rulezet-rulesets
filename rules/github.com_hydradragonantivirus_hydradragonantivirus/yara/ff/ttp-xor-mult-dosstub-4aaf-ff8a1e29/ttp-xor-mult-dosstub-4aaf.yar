rule TTP_XOR_MULT_DOSStub_4aaf {
  strings:
    $key_4aaf = { 1e c7 [2] 6a df [2] 2d dd [2] 6a cc [2] 24 c0 [2] 28 ca [2] 3f c1 [2] 24 8f [2] 19 }

  condition:
    any of them
}