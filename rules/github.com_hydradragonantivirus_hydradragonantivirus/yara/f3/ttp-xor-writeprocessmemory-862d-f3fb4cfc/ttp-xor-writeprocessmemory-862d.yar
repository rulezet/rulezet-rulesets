rule TTP_XOR_WriteProcessMemory_862d {
  strings:
    $key_862d = { d1 5f [2] e3 7d [2] e5 48 [2] cb 48 [2] f4 54 }

  condition:
    any of them
}