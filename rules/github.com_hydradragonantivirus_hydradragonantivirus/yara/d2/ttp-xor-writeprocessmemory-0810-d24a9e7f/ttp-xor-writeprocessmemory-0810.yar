rule TTP_XOR_WriteProcessMemory_0810 {
  strings:
    $key_0810 = { 5f 62 [2] 6d 40 [2] 6b 75 [2] 45 75 [2] 7a 69 }

  condition:
    any of them
}