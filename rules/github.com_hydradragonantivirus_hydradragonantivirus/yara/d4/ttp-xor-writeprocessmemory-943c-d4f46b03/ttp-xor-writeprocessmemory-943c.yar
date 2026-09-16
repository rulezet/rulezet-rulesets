rule TTP_XOR_WriteProcessMemory_943c {
  strings:
    $key_943c = { c3 4e [2] f1 6c [2] f7 59 [2] d9 59 [2] e6 45 }

  condition:
    any of them
}