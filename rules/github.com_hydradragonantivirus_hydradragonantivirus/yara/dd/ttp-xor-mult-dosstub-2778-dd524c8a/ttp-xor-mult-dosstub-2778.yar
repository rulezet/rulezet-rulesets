rule TTP_XOR_MULT_DOSStub_2778 {
  strings:
    $key_2778 = { 73 10 [2] 07 08 [2] 40 0a [2] 07 1b [2] 49 17 [2] 45 1d [2] 52 16 [2] 49 58 [2] 74 }

  condition:
    any of them
}