rule TTP_XOR_WriteProcessMemory_3224 {
  strings:
    $key_3224 = { 65 56 [2] 57 74 [2] 51 41 [2] 7f 41 [2] 40 5d }

  condition:
    any of them
}