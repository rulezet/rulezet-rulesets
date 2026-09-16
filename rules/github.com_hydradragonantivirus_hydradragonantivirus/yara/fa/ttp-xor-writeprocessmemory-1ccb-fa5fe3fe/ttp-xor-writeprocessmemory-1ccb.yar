rule TTP_XOR_WriteProcessMemory_1ccb {
  strings:
    $key_1ccb = { 4b b9 [2] 79 9b [2] 7f ae [2] 51 ae [2] 6e b2 }

  condition:
    any of them
}