rule TTP_XOR_WriteProcessMemory_2333 {
  strings:
    $key_2333 = { 74 41 [2] 46 63 [2] 40 56 [2] 6e 56 [2] 51 4a }

  condition:
    any of them
}