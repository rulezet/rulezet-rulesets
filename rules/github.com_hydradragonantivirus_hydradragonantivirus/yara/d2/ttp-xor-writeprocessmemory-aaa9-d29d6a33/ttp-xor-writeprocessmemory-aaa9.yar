rule TTP_XOR_WriteProcessMemory_aaa9 {
  strings:
    $key_aaa9 = { fd db [2] cf f9 [2] c9 cc [2] e7 cc [2] d8 d0 }

  condition:
    any of them
}