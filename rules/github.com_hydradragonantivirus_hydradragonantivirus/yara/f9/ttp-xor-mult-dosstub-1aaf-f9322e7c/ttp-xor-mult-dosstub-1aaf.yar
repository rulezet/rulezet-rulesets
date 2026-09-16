rule TTP_XOR_MULT_DOSStub_1aaf {
  strings:
    $key_1aaf = { 4e c7 [2] 3a df [2] 7d dd [2] 3a cc [2] 74 c0 [2] 78 ca [2] 6f c1 [2] 74 8f [2] 49 }

  condition:
    any of them
}