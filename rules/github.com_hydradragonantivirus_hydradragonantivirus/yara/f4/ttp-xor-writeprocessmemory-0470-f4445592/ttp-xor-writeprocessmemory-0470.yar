rule TTP_XOR_WriteProcessMemory_0470 {
  strings:
    $key_0470 = { 53 02 [2] 61 20 [2] 67 15 [2] 49 15 [2] 76 09 }

  condition:
    any of them
}