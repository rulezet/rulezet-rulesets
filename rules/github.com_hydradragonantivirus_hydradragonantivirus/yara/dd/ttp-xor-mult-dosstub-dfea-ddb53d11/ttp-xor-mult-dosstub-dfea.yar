rule TTP_XOR_MULT_DOSStub_dfea {
  strings:
    $key_dfea = { 8b 82 [2] ff 9a [2] b8 98 [2] ff 89 [2] b1 85 [2] bd 8f [2] aa 84 [2] b1 ca [2] 8c }

  condition:
    any of them
}