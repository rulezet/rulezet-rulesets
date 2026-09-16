rule TTP_XOR_WriteProcessMemory_2d39 {
  strings:
    $key_2d39 = { 7a 4b [2] 48 69 [2] 4e 5c [2] 60 5c [2] 5f 40 }

  condition:
    any of them
}