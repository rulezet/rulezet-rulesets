rule TTP_XOR_WriteProcessMemory_1b24 {
  strings:
    $key_1b24 = { 4c 56 [2] 7e 74 [2] 78 41 [2] 56 41 [2] 69 5d }

  condition:
    any of them
}