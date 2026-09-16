rule TTP_XOR_MULT_DOSStub_f167 {
  strings:
    $key_f167 = { a5 0f [2] d1 17 [2] 96 15 [2] d1 04 [2] 9f 08 [2] 93 02 [2] 84 09 [2] 9f 47 [2] a2 }

  condition:
    any of them
}