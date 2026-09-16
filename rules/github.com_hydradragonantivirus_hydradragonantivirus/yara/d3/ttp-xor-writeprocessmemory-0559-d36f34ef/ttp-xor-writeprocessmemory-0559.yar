rule TTP_XOR_WriteProcessMemory_0559 {
  strings:
    $key_0559 = { 52 2b [2] 60 09 [2] 66 3c [2] 48 3c [2] 77 20 }

  condition:
    any of them
}