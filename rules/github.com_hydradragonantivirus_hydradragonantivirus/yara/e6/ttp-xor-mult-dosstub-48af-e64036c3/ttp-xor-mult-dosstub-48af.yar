rule TTP_XOR_MULT_DOSStub_48af {
  strings:
    $key_48af = { 1c c7 [2] 68 df [2] 2f dd [2] 68 cc [2] 26 c0 [2] 2a ca [2] 3d c1 [2] 26 8f [2] 1b }

  condition:
    any of them
}