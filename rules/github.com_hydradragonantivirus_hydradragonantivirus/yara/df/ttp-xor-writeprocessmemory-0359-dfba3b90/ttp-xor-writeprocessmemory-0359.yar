rule TTP_XOR_WriteProcessMemory_0359 {
  strings:
    $key_0359 = { 54 2b [2] 66 09 [2] 60 3c [2] 4e 3c [2] 71 20 }

  condition:
    any of them
}