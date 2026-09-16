rule TTP_XOR_WriteProcessMemory_9415 {
  strings:
    $key_9415 = { c3 67 [2] f1 45 [2] f7 70 [2] d9 70 [2] e6 6c }

  condition:
    any of them
}