rule TTP_XOR_WriteProcessMemory_e348 {
  strings:
    $key_e348 = { b4 3a [2] 86 18 [2] 80 2d [2] ae 2d [2] 91 31 }

  condition:
    any of them
}