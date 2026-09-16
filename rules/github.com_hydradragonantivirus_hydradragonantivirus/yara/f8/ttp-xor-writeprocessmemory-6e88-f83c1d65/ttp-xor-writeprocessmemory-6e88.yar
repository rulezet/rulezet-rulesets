rule TTP_XOR_WriteProcessMemory_6e88 {
  strings:
    $key_6e88 = { 39 fa [2] 0b d8 [2] 0d ed [2] 23 ed [2] 1c f1 }

  condition:
    any of them
}