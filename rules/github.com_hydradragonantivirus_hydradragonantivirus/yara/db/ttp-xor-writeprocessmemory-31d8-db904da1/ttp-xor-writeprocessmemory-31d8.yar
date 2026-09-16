rule TTP_XOR_WriteProcessMemory_31d8 {
  strings:
    $key_31d8 = { 66 aa [2] 54 88 [2] 52 bd [2] 7c bd [2] 43 a1 }

  condition:
    any of them
}