rule TTP_XOR_MULT_DOSStub_68af {
  strings:
    $key_68af = { 3c c7 [2] 48 df [2] 0f dd [2] 48 cc [2] 06 c0 [2] 0a ca [2] 1d c1 [2] 06 8f [2] 3b }

  condition:
    any of them
}