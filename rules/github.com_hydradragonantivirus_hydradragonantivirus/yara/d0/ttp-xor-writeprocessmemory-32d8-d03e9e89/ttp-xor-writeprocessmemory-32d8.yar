rule TTP_XOR_WriteProcessMemory_32d8 {
  strings:
    $key_32d8 = { 65 aa [2] 57 88 [2] 51 bd [2] 7f bd [2] 40 a1 }

  condition:
    any of them
}