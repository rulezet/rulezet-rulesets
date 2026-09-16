rule TTP_XOR_WriteProcessMemory_dc88 {
  strings:
    $key_dc88 = { 8b fa [2] b9 d8 [2] bf ed [2] 91 ed [2] ae f1 }

  condition:
    any of them
}