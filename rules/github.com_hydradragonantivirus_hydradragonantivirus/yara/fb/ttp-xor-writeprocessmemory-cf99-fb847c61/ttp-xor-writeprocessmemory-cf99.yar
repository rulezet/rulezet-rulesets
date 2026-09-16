rule TTP_XOR_WriteProcessMemory_cf99 {
  strings:
    $key_cf99 = { 98 eb [2] aa c9 [2] ac fc [2] 82 fc [2] bd e0 }

  condition:
    any of them
}