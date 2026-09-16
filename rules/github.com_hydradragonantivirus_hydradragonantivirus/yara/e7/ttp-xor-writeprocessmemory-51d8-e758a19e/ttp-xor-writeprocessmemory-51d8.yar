rule TTP_XOR_WriteProcessMemory_51d8 {
  strings:
    $key_51d8 = { 06 aa [2] 34 88 [2] 32 bd [2] 1c bd [2] 23 a1 }

  condition:
    any of them
}