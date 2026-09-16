rule TTP_XOR_WriteProcessMemory_ee2b {
  strings:
    $key_ee2b = { b9 59 [2] 8b 7b [2] 8d 4e [2] a3 4e [2] 9c 52 }

  condition:
    any of them
}