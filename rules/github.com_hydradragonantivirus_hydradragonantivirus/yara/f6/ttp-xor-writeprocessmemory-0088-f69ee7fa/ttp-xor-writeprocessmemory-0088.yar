rule TTP_XOR_WriteProcessMemory_0088 {
  strings:
    $key_0088 = { 57 fa [2] 65 d8 [2] 63 ed [2] 4d ed [2] 72 f1 }

  condition:
    any of them
}