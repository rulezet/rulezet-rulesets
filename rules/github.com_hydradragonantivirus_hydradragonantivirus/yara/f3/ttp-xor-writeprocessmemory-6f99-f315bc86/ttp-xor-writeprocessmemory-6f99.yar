rule TTP_XOR_WriteProcessMemory_6f99 {
  strings:
    $key_6f99 = { 38 eb [2] 0a c9 [2] 0c fc [2] 22 fc [2] 1d e0 }

  condition:
    any of them
}