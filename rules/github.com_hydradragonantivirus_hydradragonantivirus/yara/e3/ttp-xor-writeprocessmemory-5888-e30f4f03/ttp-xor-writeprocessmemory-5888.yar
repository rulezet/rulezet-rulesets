rule TTP_XOR_WriteProcessMemory_5888 {
  strings:
    $key_5888 = { 0f fa [2] 3d d8 [2] 3b ed [2] 15 ed [2] 2a f1 }

  condition:
    any of them
}