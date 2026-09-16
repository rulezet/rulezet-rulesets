rule TTP_XOR_WriteProcessMemory_44ed {
  strings:
    $key_44ed = { 13 9f [2] 21 bd [2] 27 88 [2] 09 88 [2] 36 94 }

  condition:
    any of them
}