rule TTP_XOR_WriteProcessMemory_1f99 {
  strings:
    $key_1f99 = { 48 eb [2] 7a c9 [2] 7c fc [2] 52 fc [2] 6d e0 }

  condition:
    any of them
}