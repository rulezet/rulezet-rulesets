rule TTP_XOR_WriteProcessMemory_eef4 {
  strings:
    $key_eef4 = { b9 86 [2] 8b a4 [2] 8d 91 [2] a3 91 [2] 9c 8d }

  condition:
    any of them
}