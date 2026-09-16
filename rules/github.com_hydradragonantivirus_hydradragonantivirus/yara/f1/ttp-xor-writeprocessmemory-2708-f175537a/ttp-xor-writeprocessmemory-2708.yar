rule TTP_XOR_WriteProcessMemory_2708 {
  strings:
    $key_2708 = { 70 7a [2] 42 58 [2] 44 6d [2] 6a 6d [2] 55 71 }

  condition:
    any of them
}