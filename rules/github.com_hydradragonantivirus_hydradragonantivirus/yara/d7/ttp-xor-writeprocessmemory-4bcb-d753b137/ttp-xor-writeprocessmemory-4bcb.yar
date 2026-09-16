rule TTP_XOR_WriteProcessMemory_4bcb {
  strings:
    $key_4bcb = { 1c b9 [2] 2e 9b [2] 28 ae [2] 06 ae [2] 39 b2 }

  condition:
    any of them
}