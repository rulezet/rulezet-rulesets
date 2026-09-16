rule TTP_XOR_WriteProcessMemory_2899 {
  strings:
    $key_2899 = { 7f eb [2] 4d c9 [2] 4b fc [2] 65 fc [2] 5a e0 }

  condition:
    any of them
}