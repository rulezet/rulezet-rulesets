rule TTP_XOR_MULT_DOSStub_c056 {
  strings:
    $key_c056 = { 94 3e [2] e0 26 [2] a7 24 [2] e0 35 [2] ae 39 [2] a2 33 [2] b5 38 [2] ae 76 [2] 93 }

  condition:
    any of them
}