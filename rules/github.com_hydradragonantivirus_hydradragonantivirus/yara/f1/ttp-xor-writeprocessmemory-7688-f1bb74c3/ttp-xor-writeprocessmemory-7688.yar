rule TTP_XOR_WriteProcessMemory_7688 {
  strings:
    $key_7688 = { 21 fa [2] 13 d8 [2] 15 ed [2] 3b ed [2] 04 f1 }

  condition:
    any of them
}