rule TTP_XOR_WriteProcessMemory_8670 {
  strings:
    $key_8670 = { d1 02 [2] e3 20 [2] e5 15 [2] cb 15 [2] f4 09 }

  condition:
    any of them
}