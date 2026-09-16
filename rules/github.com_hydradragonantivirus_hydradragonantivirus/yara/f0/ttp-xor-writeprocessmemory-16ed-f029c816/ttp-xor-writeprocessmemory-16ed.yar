rule TTP_XOR_WriteProcessMemory_16ed {
  strings:
    $key_16ed = { 41 9f [2] 73 bd [2] 75 88 [2] 5b 88 [2] 64 94 }

  condition:
    any of them
}