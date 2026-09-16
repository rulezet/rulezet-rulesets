rule TTP_XOR_WriteProcessMemory_1b03 {
  strings:
    $key_1b03 = { 4c 71 [2] 7e 53 [2] 78 66 [2] 56 66 [2] 69 7a }

  condition:
    any of them
}