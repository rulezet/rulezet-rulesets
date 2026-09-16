rule TTP_XOR_WriteProcessMemory_47ed {
  strings:
    $key_47ed = { 10 9f [2] 22 bd [2] 24 88 [2] 0a 88 [2] 35 94 }

  condition:
    any of them
}