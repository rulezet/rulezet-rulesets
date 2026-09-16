rule TTP_XOR_WriteProcessMemory_5acb {
  strings:
    $key_5acb = { 0d b9 [2] 3f 9b [2] 39 ae [2] 17 ae [2] 28 b2 }

  condition:
    any of them
}