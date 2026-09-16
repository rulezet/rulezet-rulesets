rule TTP_XOR_WriteProcessMemory_e464 {
  strings:
    $key_e464 = { b3 16 [2] 81 34 [2] 87 01 [2] a9 01 [2] 96 1d }

  condition:
    any of them
}