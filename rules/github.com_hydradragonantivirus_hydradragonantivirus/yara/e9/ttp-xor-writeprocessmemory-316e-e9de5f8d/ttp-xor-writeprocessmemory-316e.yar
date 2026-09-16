rule TTP_XOR_WriteProcessMemory_316e {
  strings:
    $key_316e = { 66 1c [2] 54 3e [2] 52 0b [2] 7c 0b [2] 43 17 }

  condition:
    any of them
}