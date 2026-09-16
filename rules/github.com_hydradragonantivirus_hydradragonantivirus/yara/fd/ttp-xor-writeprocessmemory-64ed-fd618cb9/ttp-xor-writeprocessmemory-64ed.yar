rule TTP_XOR_WriteProcessMemory_64ed {
  strings:
    $key_64ed = { 33 9f [2] 01 bd [2] 07 88 [2] 29 88 [2] 16 94 }

  condition:
    any of them
}