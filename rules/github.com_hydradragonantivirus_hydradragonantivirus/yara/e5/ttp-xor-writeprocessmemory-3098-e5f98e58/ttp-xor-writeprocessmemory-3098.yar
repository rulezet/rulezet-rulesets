rule TTP_XOR_WriteProcessMemory_3098 {
  strings:
    $key_3098 = { 67 ea [2] 55 c8 [2] 53 fd [2] 7d fd [2] 42 e1 }

  condition:
    any of them
}