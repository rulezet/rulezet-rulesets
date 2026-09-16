rule TTP_XOR_WriteProcessMemory_1b23 {
  strings:
    $key_1b23 = { 4c 51 [2] 7e 73 [2] 78 46 [2] 56 46 [2] 69 5a }

  condition:
    any of them
}