rule TTP_XOR_MULT_DOSStub_ff03 {
  strings:
    $key_ff03 = { ab 6b [2] df 73 [2] 98 71 [2] df 60 [2] 91 6c [2] 9d 66 [2] 8a 6d [2] 91 23 [2] ac }

  condition:
    any of them
}