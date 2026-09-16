rule TTP_XOR_WriteProcessMemory_1b59 {
  strings:
    $key_1b59 = { 4c 2b [2] 7e 09 [2] 78 3c [2] 56 3c [2] 69 20 }

  condition:
    any of them
}