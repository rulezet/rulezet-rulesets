rule TTP_XOR_WriteProcessMemory_e159 {
  strings:
    $key_e159 = { b6 2b [2] 84 09 [2] 82 3c [2] ac 3c [2] 93 20 }

  condition:
    any of them
}