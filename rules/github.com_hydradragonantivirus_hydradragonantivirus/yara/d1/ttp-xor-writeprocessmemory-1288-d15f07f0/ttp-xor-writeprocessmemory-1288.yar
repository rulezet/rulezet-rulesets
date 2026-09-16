rule TTP_XOR_WriteProcessMemory_1288 {
  strings:
    $key_1288 = { 45 fa [2] 77 d8 [2] 71 ed [2] 5f ed [2] 60 f1 }

  condition:
    any of them
}