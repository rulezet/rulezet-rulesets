rule TTP_XOR_WriteProcessMemory_52f4 {
  strings:
    $key_52f4 = { 05 86 [2] 37 a4 [2] 31 91 [2] 1f 91 [2] 20 8d }

  condition:
    any of them
}