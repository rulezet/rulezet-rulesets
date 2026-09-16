rule TTP_XOR_MULT_DOSStub_3618 {
  strings:
    $key_3618 = { 62 70 [2] 16 68 [2] 51 6a [2] 16 7b [2] 58 77 [2] 54 7d [2] 43 76 [2] 58 38 [2] 65 }

  condition:
    any of them
}