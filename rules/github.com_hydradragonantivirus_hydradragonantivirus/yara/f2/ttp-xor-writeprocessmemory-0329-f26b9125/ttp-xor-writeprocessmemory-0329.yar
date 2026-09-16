rule TTP_XOR_WriteProcessMemory_0329 {
  strings:
    $key_0329 = { 54 5b [2] 66 79 [2] 60 4c [2] 4e 4c [2] 71 50 }

  condition:
    any of them
}