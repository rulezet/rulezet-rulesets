rule TTP_XOR_WriteProcessMemory_e31d {
  strings:
    $key_e31d = { b4 6f [2] 86 4d [2] 80 78 [2] ae 78 [2] 91 64 }

  condition:
    any of them
}