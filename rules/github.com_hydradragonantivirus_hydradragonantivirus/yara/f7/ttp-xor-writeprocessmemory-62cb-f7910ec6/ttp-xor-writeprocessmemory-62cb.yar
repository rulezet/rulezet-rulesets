rule TTP_XOR_WriteProcessMemory_62cb {
  strings:
    $key_62cb = { 35 b9 [2] 07 9b [2] 01 ae [2] 2f ae [2] 10 b2 }

  condition:
    any of them
}