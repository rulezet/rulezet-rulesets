rule TTP_XOR_WriteProcessMemory_4b33 {
  strings:
    $key_4b33 = { 1c 41 [2] 2e 63 [2] 28 56 [2] 06 56 [2] 39 4a }

  condition:
    any of them
}