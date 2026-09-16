rule TTP_XOR_MULT_DOSStub_c0ae {
  strings:
    $key_c0ae = { 94 c6 [2] e0 de [2] a7 dc [2] e0 cd [2] ae c1 [2] a2 cb [2] b5 c0 [2] ae 8e [2] 93 }

  condition:
    any of them
}