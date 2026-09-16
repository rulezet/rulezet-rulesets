rule TTP_XOR_WriteProcessMemory_830c {
  strings:
    $key_830c = { d4 7e [2] e6 5c [2] e0 69 [2] ce 69 [2] f1 75 }

  condition:
    any of them
}