rule TTP_XOR_WriteProcessMemory_e16e {
  strings:
    $key_e16e = { b6 1c [2] 84 3e [2] 82 0b [2] ac 0b [2] 93 17 }

  condition:
    any of them
}