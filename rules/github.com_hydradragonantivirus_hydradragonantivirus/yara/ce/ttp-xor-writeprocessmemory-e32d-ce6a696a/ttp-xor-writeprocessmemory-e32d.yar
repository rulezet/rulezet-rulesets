rule TTP_XOR_WriteProcessMemory_e32d {
  strings:
    $key_e32d = { b4 5f [2] 86 7d [2] 80 48 [2] ae 48 [2] 91 54 }

  condition:
    any of them
}