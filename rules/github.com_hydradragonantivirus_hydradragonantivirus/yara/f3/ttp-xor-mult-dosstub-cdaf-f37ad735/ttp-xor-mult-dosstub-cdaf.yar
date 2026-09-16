rule TTP_XOR_MULT_DOSStub_cdaf {
  strings:
    $key_cdaf = { 99 c7 [2] ed df [2] aa dd [2] ed cc [2] a3 c0 [2] af ca [2] b8 c1 [2] a3 8f [2] 9e }

  condition:
    any of them
}