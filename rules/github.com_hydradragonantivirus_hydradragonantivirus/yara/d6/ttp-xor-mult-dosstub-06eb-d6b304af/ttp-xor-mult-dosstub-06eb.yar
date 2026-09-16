rule TTP_XOR_MULT_DOSStub_06eb {
  strings:
    $key_06eb = { 52 83 [2] 26 9b [2] 61 99 [2] 26 88 [2] 68 84 [2] 64 8e [2] 73 85 [2] 68 cb [2] 55 }

  condition:
    any of them
}