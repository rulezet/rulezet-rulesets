rule TTP_XOR_WriteProcessMemory_1439 {
  strings:
    $key_1439 = { 43 4b [2] 71 69 [2] 77 5c [2] 59 5c [2] 66 40 }

  condition:
    any of them
}