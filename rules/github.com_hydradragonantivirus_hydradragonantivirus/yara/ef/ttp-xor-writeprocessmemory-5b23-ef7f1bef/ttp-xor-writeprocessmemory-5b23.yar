rule TTP_XOR_WriteProcessMemory_5b23 {
  strings:
    $key_5b23 = { 0c 51 [2] 3e 73 [2] 38 46 [2] 16 46 [2] 29 5a }

  condition:
    any of them
}