rule TTP_XOR_WriteProcessMemory_d89c {
  strings:
    $key_d89c = { 8f ee [2] bd cc [2] bb f9 [2] 95 f9 [2] aa e5 }

  condition:
    any of them
}