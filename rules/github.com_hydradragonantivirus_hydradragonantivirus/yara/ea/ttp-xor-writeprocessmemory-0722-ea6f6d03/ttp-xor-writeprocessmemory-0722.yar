rule TTP_XOR_WriteProcessMemory_0722 {
  strings:
    $key_0722 = { 50 50 [2] 62 72 [2] 64 47 [2] 4a 47 [2] 75 5b }

  condition:
    any of them
}