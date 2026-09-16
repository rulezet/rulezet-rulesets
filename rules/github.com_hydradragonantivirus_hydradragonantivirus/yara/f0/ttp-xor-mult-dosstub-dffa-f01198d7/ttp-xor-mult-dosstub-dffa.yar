rule TTP_XOR_MULT_DOSStub_dffa {
  strings:
    $key_dffa = { 8b 92 [2] ff 8a [2] b8 88 [2] ff 99 [2] b1 95 [2] bd 9f [2] aa 94 [2] b1 da [2] 8c }

  condition:
    any of them
}