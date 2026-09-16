rule TTP_XOR_WriteProcessMemory_e368 {
  strings:
    $key_e368 = { b4 1a [2] 86 38 [2] 80 0d [2] ae 0d [2] 91 11 }

  condition:
    any of them
}