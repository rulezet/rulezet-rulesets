rule TTP_XOR_WriteProcessMemory_6469 {
  strings:
    $key_6469 = { 33 1b [2] 01 39 [2] 07 0c [2] 29 0c [2] 16 10 }

  condition:
    any of them
}