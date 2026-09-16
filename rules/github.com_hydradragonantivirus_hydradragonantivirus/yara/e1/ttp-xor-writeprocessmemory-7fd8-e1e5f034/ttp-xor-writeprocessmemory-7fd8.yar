rule TTP_XOR_WriteProcessMemory_7fd8 {
  strings:
    $key_7fd8 = { 28 aa [2] 1a 88 [2] 1c bd [2] 32 bd [2] 0d a1 }

  condition:
    any of them
}