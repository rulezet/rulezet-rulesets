rule TTP_XOR_WriteProcessMemory_22ed {
  strings:
    $key_22ed = { 75 9f [2] 47 bd [2] 41 88 [2] 6f 88 [2] 50 94 }

  condition:
    any of them
}