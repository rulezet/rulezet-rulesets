rule TTP_XOR_MULT_DOSStub_ff24 {
  strings:
    $key_ff24 = { ab 4c [2] df 54 [2] 98 56 [2] df 47 [2] 91 4b [2] 9d 41 [2] 8a 4a [2] 91 04 [2] ac }

  condition:
    any of them
}