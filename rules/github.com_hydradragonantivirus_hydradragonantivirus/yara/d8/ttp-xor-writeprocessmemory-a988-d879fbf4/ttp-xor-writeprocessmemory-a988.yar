rule TTP_XOR_WriteProcessMemory_a988 {
  strings:
    $key_a988 = { fe fa [2] cc d8 [2] ca ed [2] e4 ed [2] db f1 }

  condition:
    any of them
}