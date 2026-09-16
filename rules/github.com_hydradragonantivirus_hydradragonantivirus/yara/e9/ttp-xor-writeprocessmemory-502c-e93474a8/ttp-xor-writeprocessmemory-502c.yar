rule TTP_XOR_WriteProcessMemory_502c {
  strings:
    $key_502c = { 07 5e [2] 35 7c [2] 33 49 [2] 1d 49 [2] 22 55 }

  condition:
    any of them
}