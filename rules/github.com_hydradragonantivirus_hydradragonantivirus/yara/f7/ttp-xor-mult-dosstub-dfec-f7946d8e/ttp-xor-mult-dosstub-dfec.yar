rule TTP_XOR_MULT_DOSStub_dfec {
  strings:
    $key_dfec = { 8b 84 [2] ff 9c [2] b8 9e [2] ff 8f [2] b1 83 [2] bd 89 [2] aa 82 [2] b1 cc [2] 8c }

  condition:
    any of them
}