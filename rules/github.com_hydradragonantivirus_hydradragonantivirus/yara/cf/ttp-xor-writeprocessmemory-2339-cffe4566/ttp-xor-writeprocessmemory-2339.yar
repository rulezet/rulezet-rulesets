rule TTP_XOR_WriteProcessMemory_2339 {
  strings:
    $key_2339 = { 74 4b [2] 46 69 [2] 40 5c [2] 6e 5c [2] 51 40 }

  condition:
    any of them
}