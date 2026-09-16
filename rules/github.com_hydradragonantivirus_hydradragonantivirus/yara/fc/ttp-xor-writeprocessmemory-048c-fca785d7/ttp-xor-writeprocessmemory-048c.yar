rule TTP_XOR_WriteProcessMemory_048c {
  strings:
    $key_048c = { 53 fe [2] 61 dc [2] 67 e9 [2] 49 e9 [2] 76 f5 }

  condition:
    any of them
}