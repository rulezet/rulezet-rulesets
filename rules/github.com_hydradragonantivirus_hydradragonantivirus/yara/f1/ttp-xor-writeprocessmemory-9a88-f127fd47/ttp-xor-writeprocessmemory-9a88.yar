rule TTP_XOR_WriteProcessMemory_9a88 {
  strings:
    $key_9a88 = { cd fa [2] ff d8 [2] f9 ed [2] d7 ed [2] e8 f1 }

  condition:
    any of them
}