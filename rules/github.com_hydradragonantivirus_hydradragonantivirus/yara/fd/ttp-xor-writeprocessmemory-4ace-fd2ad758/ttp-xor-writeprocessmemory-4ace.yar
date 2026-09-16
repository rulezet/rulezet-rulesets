rule TTP_XOR_WriteProcessMemory_4ace {
  strings:
    $key_4ace = { 1d bc [2] 2f 9e [2] 29 ab [2] 07 ab [2] 38 b7 }

  condition:
    any of them
}