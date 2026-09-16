rule TTP_XOR_WriteProcessMemory_e35d {
  strings:
    $key_e35d = { b4 2f [2] 86 0d [2] 80 38 [2] ae 38 [2] 91 24 }

  condition:
    any of them
}