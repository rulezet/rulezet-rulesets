rule TTP_XOR_WriteProcessMemory_22d8 {
  strings:
    $key_22d8 = { 75 aa [2] 47 88 [2] 41 bd [2] 6f bd [2] 50 a1 }

  condition:
    any of them
}