rule TTP_XOR_WriteProcessMemory_ffd8 {
  strings:
    $key_ffd8 = { a8 aa [2] 9a 88 [2] 9c bd [2] b2 bd [2] 8d a1 }

  condition:
    any of them
}