rule TTP_XOR_WriteProcessMemory_2b23 {
  strings:
    $key_2b23 = { 7c 51 [2] 4e 73 [2] 48 46 [2] 66 46 [2] 59 5a }

  condition:
    any of them
}