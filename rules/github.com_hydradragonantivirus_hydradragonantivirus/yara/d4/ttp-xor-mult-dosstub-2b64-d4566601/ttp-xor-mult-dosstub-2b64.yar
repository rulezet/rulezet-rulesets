rule TTP_XOR_MULT_DOSStub_2b64 {
  strings:
    $key_2b64 = { 7f 0c [2] 0b 14 [2] 4c 16 [2] 0b 07 [2] 45 0b [2] 49 01 [2] 5e 0a [2] 45 44 [2] 78 }

  condition:
    any of them
}