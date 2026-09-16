rule TTP_XOR_MULT_DOSStub_c30f {
  strings:
    $key_c30f = { 97 67 [2] e3 7f [2] a4 7d [2] e3 6c [2] ad 60 [2] a1 6a [2] b6 61 [2] ad 2f [2] 90 }

  condition:
    any of them
}