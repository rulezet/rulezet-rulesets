rule TTP_XOR_WriteProcessMemory_08ed {
  strings:
    $key_08ed = { 5f 9f [2] 6d bd [2] 6b 88 [2] 45 88 [2] 7a 94 }

  condition:
    any of them
}