rule TTP_XOR_WriteProcessMemory_5b59 {
  strings:
    $key_5b59 = { 0c 2b [2] 3e 09 [2] 38 3c [2] 16 3c [2] 29 20 }

  condition:
    any of them
}