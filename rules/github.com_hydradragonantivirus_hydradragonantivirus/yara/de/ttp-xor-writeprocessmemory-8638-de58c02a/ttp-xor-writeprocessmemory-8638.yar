rule TTP_XOR_WriteProcessMemory_8638 {
  strings:
    $key_8638 = { d1 4a [2] e3 68 [2] e5 5d [2] cb 5d [2] f4 41 }

  condition:
    any of them
}