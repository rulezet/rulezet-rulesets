rule TTP_XOR_WriteProcessMemory_323c {
  strings:
    $key_323c = { 65 4e [2] 57 6c [2] 51 59 [2] 7f 59 [2] 40 45 }

  condition:
    any of them
}