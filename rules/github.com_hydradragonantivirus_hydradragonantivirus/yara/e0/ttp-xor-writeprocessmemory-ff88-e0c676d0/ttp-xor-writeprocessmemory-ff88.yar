rule TTP_XOR_WriteProcessMemory_ff88 {
  strings:
    $key_ff88 = { a8 fa [2] 9a d8 [2] 9c ed [2] b2 ed [2] 8d f1 }

  condition:
    any of them
}