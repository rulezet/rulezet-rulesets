rule TTP_XOR_MULT_DOSStub_06af {
  strings:
    $key_06af = { 52 c7 [2] 26 df [2] 61 dd [2] 26 cc [2] 68 c0 [2] 64 ca [2] 73 c1 [2] 68 8f [2] 55 }

  condition:
    any of them
}