rule TTP_XOR_WriteProcessMemory_9315 {
  strings:
    $key_9315 = { c4 67 [2] f6 45 [2] f0 70 [2] de 70 [2] e1 6c }

  condition:
    any of them
}