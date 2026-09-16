rule TTP_XOR_WriteProcessMemory_00ed {
  strings:
    $key_00ed = { 57 9f [2] 65 bd [2] 63 88 [2] 4d 88 [2] 72 94 }

  condition:
    any of them
}