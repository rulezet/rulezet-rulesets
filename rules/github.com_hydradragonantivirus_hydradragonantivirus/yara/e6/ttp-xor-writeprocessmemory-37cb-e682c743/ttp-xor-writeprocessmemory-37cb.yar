rule TTP_XOR_WriteProcessMemory_37cb {
  strings:
    $key_37cb = { 60 b9 [2] 52 9b [2] 54 ae [2] 7a ae [2] 45 b2 }

  condition:
    any of them
}