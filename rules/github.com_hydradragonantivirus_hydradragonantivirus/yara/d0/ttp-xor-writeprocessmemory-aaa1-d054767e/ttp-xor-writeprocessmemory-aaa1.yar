rule TTP_XOR_WriteProcessMemory_aaa1 {
  strings:
    $key_aaa1 = { fd d3 [2] cf f1 [2] c9 c4 [2] e7 c4 [2] d8 d8 }

  condition:
    any of them
}