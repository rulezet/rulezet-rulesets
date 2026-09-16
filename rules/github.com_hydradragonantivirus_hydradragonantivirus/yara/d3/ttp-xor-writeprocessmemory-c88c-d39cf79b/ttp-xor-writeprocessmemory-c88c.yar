rule TTP_XOR_WriteProcessMemory_c88c {
  strings:
    $key_c88c = { 9f fe [2] ad dc [2] ab e9 [2] 85 e9 [2] ba f5 }

  condition:
    any of them
}