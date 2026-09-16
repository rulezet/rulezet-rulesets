rule TTP_XOR_WriteProcessMemory_0988 {
  strings:
    $key_0988 = { 5e fa [2] 6c d8 [2] 6a ed [2] 44 ed [2] 7b f1 }

  condition:
    any of them
}