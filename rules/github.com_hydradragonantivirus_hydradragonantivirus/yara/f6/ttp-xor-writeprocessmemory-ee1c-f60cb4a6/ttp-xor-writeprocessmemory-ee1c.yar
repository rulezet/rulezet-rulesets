rule TTP_XOR_WriteProcessMemory_ee1c {
  strings:
    $key_ee1c = { b9 6e [2] 8b 4c [2] 8d 79 [2] a3 79 [2] 9c 65 }

  condition:
    any of them
}