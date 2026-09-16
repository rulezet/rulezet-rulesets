rule TTP_XOR_WriteProcessMemory_04cb {
  strings:
    $key_04cb = { 53 b9 [2] 61 9b [2] 67 ae [2] 49 ae [2] 76 b2 }

  condition:
    any of them
}