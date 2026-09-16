rule TTP_XOR_WriteProcessMemory_e30c {
  strings:
    $key_e30c = { b4 7e [2] 86 5c [2] 80 69 [2] ae 69 [2] 91 75 }

  condition:
    any of them
}