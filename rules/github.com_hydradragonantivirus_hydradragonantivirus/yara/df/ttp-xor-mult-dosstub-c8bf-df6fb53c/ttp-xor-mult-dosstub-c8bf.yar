rule TTP_XOR_MULT_DOSStub_c8bf {
  strings:
    $key_c8bf = { 9c d7 [2] e8 cf [2] af cd [2] e8 dc [2] a6 d0 [2] aa da [2] bd d1 [2] a6 9f [2] 9b }

  condition:
    any of them
}