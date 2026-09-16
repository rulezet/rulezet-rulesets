rule TTP_XOR_MULT_DOSStub_d618 {
  strings:
    $key_d618 = { 82 70 [2] f6 68 [2] b1 6a [2] f6 7b [2] b8 77 [2] b4 7d [2] a3 76 [2] b8 38 [2] 85 }

  condition:
    any of them
}