rule TTP_XOR_WriteProcessMemory_4b19 {
  strings:
    $key_4b19 = { 1c 6b [2] 2e 49 [2] 28 7c [2] 06 7c [2] 39 60 }

  condition:
    any of them
}