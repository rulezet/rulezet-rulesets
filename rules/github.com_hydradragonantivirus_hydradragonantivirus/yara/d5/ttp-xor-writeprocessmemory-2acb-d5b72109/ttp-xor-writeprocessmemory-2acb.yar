rule TTP_XOR_WriteProcessMemory_2acb {
  strings:
    $key_2acb = { 7d b9 [2] 4f 9b [2] 49 ae [2] 67 ae [2] 58 b2 }

  condition:
    any of them
}