rule TTP_XOR_WriteProcessMemory_762c {
  strings:
    $key_762c = { 21 5e [2] 13 7c [2] 15 49 [2] 3b 49 [2] 04 55 }

  condition:
    any of them
}