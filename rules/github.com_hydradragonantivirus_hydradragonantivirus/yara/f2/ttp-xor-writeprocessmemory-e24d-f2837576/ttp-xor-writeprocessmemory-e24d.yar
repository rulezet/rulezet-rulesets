rule TTP_XOR_WriteProcessMemory_e24d {
  strings:
    $key_e24d = { b5 3f [2] 87 1d [2] 81 28 [2] af 28 [2] 90 34 }

  condition:
    any of them
}