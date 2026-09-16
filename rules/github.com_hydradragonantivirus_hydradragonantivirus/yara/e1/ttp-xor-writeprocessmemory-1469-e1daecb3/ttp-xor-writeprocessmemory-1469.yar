rule TTP_XOR_WriteProcessMemory_1469 {
  strings:
    $key_1469 = { 43 1b [2] 71 39 [2] 77 0c [2] 59 0c [2] 66 10 }

  condition:
    any of them
}