rule TTP_XOR_WriteProcessMemory_4b24 {
  strings:
    $key_4b24 = { 1c 56 [2] 2e 74 [2] 28 41 [2] 06 41 [2] 39 5d }

  condition:
    any of them
}