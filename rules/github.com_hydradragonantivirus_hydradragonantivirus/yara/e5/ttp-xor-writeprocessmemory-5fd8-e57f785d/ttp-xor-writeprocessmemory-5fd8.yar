rule TTP_XOR_WriteProcessMemory_5fd8 {
  strings:
    $key_5fd8 = { 08 aa [2] 3a 88 [2] 3c bd [2] 12 bd [2] 2d a1 }

  condition:
    any of them
}