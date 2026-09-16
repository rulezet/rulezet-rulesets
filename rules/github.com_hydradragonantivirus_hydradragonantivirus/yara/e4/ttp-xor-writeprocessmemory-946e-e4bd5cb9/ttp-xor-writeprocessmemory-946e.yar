rule TTP_XOR_WriteProcessMemory_946e {
  strings:
    $key_946e = { c3 1c [2] f1 3e [2] f7 0b [2] d9 0b [2] e6 17 }

  condition:
    any of them
}