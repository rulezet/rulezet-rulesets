rule TTP_XOR_WriteProcessMemory_5ccb {
  strings:
    $key_5ccb = { 0b b9 [2] 39 9b [2] 3f ae [2] 11 ae [2] 2e b2 }

  condition:
    any of them
}