rule TTP_XOR_MULT_DOSStub_c60f {
  strings:
    $key_c60f = { 92 67 [2] e6 7f [2] a1 7d [2] e6 6c [2] a8 60 [2] a4 6a [2] b3 61 [2] a8 2f [2] 95 }

  condition:
    any of them
}