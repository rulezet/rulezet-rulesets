rule TTP_XOR_WriteProcessMemory_4ce4 {
  strings:
    $key_4ce4 = { 1b 96 [2] 29 b4 [2] 2f 81 [2] 01 81 [2] 3e 9d }

  condition:
    any of them
}