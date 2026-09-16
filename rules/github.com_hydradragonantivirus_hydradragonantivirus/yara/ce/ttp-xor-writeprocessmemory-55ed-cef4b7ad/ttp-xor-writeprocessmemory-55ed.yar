rule TTP_XOR_WriteProcessMemory_55ed {
  strings:
    $key_55ed = { 02 9f [2] 30 bd [2] 36 88 [2] 18 88 [2] 27 94 }

  condition:
    any of them
}