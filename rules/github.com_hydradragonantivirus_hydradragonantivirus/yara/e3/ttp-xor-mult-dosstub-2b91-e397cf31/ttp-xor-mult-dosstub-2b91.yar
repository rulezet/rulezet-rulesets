rule TTP_XOR_MULT_DOSStub_2b91 {
  strings:
    $key_2b91 = { 7f f9 [2] 0b e1 [2] 4c e3 [2] 0b f2 [2] 45 fe [2] 49 f4 [2] 5e ff [2] 45 b1 [2] 78 }

  condition:
    any of them
}