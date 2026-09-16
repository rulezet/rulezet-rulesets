rule TTP_XOR_MULT_DOSStub_cdfc {
  strings:
    $key_cdfc = { 99 94 [2] ed 8c [2] aa 8e [2] ed 9f [2] a3 93 [2] af 99 [2] b8 92 [2] a3 dc [2] 9e }

  condition:
    any of them
}