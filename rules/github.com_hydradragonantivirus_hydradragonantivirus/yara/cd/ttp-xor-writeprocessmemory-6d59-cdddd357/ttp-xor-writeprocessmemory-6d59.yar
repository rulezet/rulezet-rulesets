rule TTP_XOR_WriteProcessMemory_6d59 {
  strings:
    $key_6d59 = { 3a 2b [2] 08 09 [2] 0e 3c [2] 20 3c [2] 1f 20 }

  condition:
    any of them
}