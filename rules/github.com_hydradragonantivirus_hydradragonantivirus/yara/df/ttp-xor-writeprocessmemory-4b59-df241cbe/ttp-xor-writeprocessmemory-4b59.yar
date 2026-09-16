rule TTP_XOR_WriteProcessMemory_4b59 {
  strings:
    $key_4b59 = { 1c 2b [2] 2e 09 [2] 28 3c [2] 06 3c [2] 39 20 }

  condition:
    any of them
}