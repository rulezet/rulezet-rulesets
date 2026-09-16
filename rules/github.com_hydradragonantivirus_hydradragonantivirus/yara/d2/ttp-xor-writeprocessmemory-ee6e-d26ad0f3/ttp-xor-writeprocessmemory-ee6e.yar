rule TTP_XOR_WriteProcessMemory_ee6e {
  strings:
    $key_ee6e = { b9 1c [2] 8b 3e [2] 8d 0b [2] a3 0b [2] 9c 17 }

  condition:
    any of them
}