rule TTP_XOR_WriteProcessMemory_913c {
  strings:
    $key_913c = { c6 4e [2] f4 6c [2] f2 59 [2] dc 59 [2] e3 45 }

  condition:
    any of them
}