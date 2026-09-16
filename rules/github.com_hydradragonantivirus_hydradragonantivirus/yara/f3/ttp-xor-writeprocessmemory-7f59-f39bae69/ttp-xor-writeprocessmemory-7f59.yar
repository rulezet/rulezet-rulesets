rule TTP_XOR_WriteProcessMemory_7f59 {
  strings:
    $key_7f59 = { 28 2b [2] 1a 09 [2] 1c 3c [2] 32 3c [2] 0d 20 }

  condition:
    any of them
}