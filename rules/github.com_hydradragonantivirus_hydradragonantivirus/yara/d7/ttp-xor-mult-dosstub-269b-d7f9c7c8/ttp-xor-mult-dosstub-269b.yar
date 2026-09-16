rule TTP_XOR_MULT_DOSStub_269b {
  strings:
    $key_269b = { 72 f3 [2] 06 eb [2] 41 e9 [2] 06 f8 [2] 48 f4 [2] 44 fe [2] 53 f5 [2] 48 bb [2] 75 }

  condition:
    any of them
}