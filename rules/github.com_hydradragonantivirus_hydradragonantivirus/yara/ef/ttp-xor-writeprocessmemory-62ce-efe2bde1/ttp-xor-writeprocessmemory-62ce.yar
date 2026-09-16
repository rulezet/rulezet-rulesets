rule TTP_XOR_WriteProcessMemory_62ce {
  strings:
    $key_62ce = { 35 bc [2] 07 9e [2] 01 ab [2] 2f ab [2] 10 b7 }

  condition:
    any of them
}