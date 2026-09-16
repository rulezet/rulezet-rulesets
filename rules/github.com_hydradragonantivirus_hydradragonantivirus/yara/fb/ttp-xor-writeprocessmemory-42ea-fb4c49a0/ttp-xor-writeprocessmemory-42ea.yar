rule TTP_XOR_WriteProcessMemory_42ea {
  strings:
    $key_42ea = { 15 98 [2] 27 ba [2] 21 8f [2] 0f 8f [2] 30 93 }

  condition:
    any of them
}