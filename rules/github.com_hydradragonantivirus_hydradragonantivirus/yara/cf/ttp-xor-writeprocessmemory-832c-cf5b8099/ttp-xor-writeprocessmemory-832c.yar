rule TTP_XOR_WriteProcessMemory_832c {
  strings:
    $key_832c = { d4 5e [2] e6 7c [2] e0 49 [2] ce 49 [2] f1 55 }

  condition:
    any of them
}