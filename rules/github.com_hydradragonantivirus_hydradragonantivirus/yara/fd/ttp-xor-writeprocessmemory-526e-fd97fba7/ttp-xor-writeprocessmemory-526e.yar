rule TTP_XOR_WriteProcessMemory_526e {
  strings:
    $key_526e = { 05 1c [2] 37 3e [2] 31 0b [2] 1f 0b [2] 20 17 }

  condition:
    any of them
}