rule TTP_XOR_WriteProcessMemory_61f4 {
  strings:
    $key_61f4 = { 36 86 [2] 04 a4 [2] 02 91 [2] 2c 91 [2] 13 8d }

  condition:
    any of them
}