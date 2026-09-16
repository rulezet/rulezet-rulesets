rule TTP_XOR_WriteProcessMemory_6688 {
  strings:
    $key_6688 = { 31 fa [2] 03 d8 [2] 05 ed [2] 2b ed [2] 14 f1 }

  condition:
    any of them
}