rule TTP_XOR_MULT_DOSStub_ffe0 {
  strings:
    $key_ffe0 = { ab 88 [2] df 90 [2] 98 92 [2] df 83 [2] 91 8f [2] 9d 85 [2] 8a 8e [2] 91 c0 [2] ac }

  condition:
    any of them
}