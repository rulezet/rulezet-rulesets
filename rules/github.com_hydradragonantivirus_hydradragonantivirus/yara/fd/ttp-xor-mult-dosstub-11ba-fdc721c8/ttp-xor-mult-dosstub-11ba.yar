rule TTP_XOR_MULT_DOSStub_11ba {
  strings:
    $key_11ba = { 45 d2 [2] 31 ca [2] 76 c8 [2] 31 d9 [2] 7f d5 [2] 73 df [2] 64 d4 [2] 7f 9a [2] 42 }

  condition:
    any of them
}