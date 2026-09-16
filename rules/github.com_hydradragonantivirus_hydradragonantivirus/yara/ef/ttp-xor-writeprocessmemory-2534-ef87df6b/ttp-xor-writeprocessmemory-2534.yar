rule TTP_XOR_WriteProcessMemory_2534 {
  strings:
    $key_2534 = { 72 46 [2] 40 64 [2] 46 51 [2] 68 51 [2] 57 4d }

  condition:
    any of them
}