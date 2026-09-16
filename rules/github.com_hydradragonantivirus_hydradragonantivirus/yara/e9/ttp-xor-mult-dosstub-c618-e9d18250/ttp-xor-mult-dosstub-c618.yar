rule TTP_XOR_MULT_DOSStub_c618 {
  strings:
    $key_c618 = { 92 70 [2] e6 68 [2] a1 6a [2] e6 7b [2] a8 77 [2] a4 7d [2] b3 76 [2] a8 38 [2] 95 }

  condition:
    any of them
}