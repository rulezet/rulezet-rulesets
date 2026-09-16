rule TTP_XOR_WriteProcessMemory_6b34 {
  strings:
    $key_6b34 = { 3c 46 [2] 0e 64 [2] 08 51 [2] 26 51 [2] 19 4d }

  condition:
    any of them
}