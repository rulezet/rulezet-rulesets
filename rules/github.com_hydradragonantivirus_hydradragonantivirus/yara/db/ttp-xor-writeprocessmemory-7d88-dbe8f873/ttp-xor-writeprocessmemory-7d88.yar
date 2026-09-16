rule TTP_XOR_WriteProcessMemory_7d88 {
  strings:
    $key_7d88 = { 2a fa [2] 18 d8 [2] 1e ed [2] 30 ed [2] 0f f1 }

  condition:
    any of them
}