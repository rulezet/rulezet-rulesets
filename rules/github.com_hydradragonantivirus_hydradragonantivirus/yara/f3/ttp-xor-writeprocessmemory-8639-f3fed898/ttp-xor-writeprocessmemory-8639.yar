rule TTP_XOR_WriteProcessMemory_8639 {
  strings:
    $key_8639 = { d1 4b [2] e3 69 [2] e5 5c [2] cb 5c [2] f4 40 }

  condition:
    any of them
}