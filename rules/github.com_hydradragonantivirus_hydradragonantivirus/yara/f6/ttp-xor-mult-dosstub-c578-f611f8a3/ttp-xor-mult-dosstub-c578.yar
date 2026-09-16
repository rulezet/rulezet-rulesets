rule TTP_XOR_MULT_DOSStub_c578 {
  strings:
    $key_c578 = { 91 10 [2] e5 08 [2] a2 0a [2] e5 1b [2] ab 17 [2] a7 1d [2] b0 16 [2] ab 58 [2] 96 }

  condition:
    any of them
}