rule TTP_XOR_MULT_DOSStub_6618 {
  strings:
    $key_6618 = { 32 70 [2] 46 68 [2] 01 6a [2] 46 7b [2] 08 77 [2] 04 7d [2] 13 76 [2] 08 38 [2] 35 }

  condition:
    any of them
}