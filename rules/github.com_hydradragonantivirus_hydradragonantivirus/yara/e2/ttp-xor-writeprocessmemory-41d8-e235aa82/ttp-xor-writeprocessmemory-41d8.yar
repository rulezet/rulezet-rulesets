rule TTP_XOR_WriteProcessMemory_41d8 {
  strings:
    $key_41d8 = { 16 aa [2] 24 88 [2] 22 bd [2] 0c bd [2] 33 a1 }

  condition:
    any of them
}