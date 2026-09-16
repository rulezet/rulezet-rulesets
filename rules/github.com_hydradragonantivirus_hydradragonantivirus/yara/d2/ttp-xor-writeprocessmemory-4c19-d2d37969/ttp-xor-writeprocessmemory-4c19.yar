rule TTP_XOR_WriteProcessMemory_4c19 {
  strings:
    $key_4c19 = { 1b 6b [2] 29 49 [2] 2f 7c [2] 01 7c [2] 3e 60 }

  condition:
    any of them
}