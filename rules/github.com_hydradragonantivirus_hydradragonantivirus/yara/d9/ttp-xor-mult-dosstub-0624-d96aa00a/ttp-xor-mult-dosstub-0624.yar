rule TTP_XOR_MULT_DOSStub_0624 {
  strings:
    $key_0624 = { 52 4c [2] 26 54 [2] 61 56 [2] 26 47 [2] 68 4b [2] 64 41 [2] 73 4a [2] 68 04 [2] 55 }

  condition:
    any of them
}