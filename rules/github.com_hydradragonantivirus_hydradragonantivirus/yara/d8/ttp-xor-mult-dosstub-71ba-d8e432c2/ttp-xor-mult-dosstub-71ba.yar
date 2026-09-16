rule TTP_XOR_MULT_DOSStub_71ba {
  strings:
    $key_71ba = { 25 d2 [2] 51 ca [2] 16 c8 [2] 51 d9 [2] 1f d5 [2] 13 df [2] 04 d4 [2] 1f 9a [2] 22 }

  condition:
    any of them
}