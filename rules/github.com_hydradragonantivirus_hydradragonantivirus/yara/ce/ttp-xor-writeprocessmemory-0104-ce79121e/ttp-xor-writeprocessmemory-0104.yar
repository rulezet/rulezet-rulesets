rule TTP_XOR_WriteProcessMemory_0104 {
  strings:
    $key_0104 = { 56 76 [2] 64 54 [2] 62 61 [2] 4c 61 [2] 73 7d }

  condition:
    any of them
}