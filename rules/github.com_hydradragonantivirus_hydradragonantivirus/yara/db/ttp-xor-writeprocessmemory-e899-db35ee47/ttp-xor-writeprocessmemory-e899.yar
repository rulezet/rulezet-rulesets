rule TTP_XOR_WriteProcessMemory_e899 {
  strings:
    $key_e899 = { bf eb [2] 8d c9 [2] 8b fc [2] a5 fc [2] 9a e0 }

  condition:
    any of them
}