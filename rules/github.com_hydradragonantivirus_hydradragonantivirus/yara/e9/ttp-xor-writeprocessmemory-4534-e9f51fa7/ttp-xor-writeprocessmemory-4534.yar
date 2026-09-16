rule TTP_XOR_WriteProcessMemory_4534 {
  strings:
    $key_4534 = { 12 46 [2] 20 64 [2] 26 51 [2] 08 51 [2] 37 4d }

  condition:
    any of them
}