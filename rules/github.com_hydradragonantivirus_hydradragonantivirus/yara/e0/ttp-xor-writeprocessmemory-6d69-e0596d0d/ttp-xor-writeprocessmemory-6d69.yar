rule TTP_XOR_WriteProcessMemory_6d69 {
  strings:
    $key_6d69 = { 3a 1b [2] 08 39 [2] 0e 0c [2] 20 0c [2] 1f 10 }

  condition:
    any of them
}