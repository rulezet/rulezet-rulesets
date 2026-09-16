rule TTP_XOR_WriteProcessMemory_3b24 {
  strings:
    $key_3b24 = { 6c 56 [2] 5e 74 [2] 58 41 [2] 76 41 [2] 49 5d }

  condition:
    any of them
}