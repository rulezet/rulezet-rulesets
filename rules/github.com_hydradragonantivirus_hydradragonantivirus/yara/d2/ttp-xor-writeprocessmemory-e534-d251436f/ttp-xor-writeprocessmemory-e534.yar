rule TTP_XOR_WriteProcessMemory_e534 {
  strings:
    $key_e534 = { b2 46 [2] 80 64 [2] 86 51 [2] a8 51 [2] 97 4d }

  condition:
    any of them
}