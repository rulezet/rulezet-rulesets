rule TTP_XOR_WriteProcessMemory_8669 {
  strings:
    $key_8669 = { d1 1b [2] e3 39 [2] e5 0c [2] cb 0c [2] f4 10 }

  condition:
    any of them
}