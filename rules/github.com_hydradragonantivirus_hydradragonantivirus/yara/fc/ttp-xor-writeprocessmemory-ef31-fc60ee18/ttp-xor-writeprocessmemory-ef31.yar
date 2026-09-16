rule TTP_XOR_WriteProcessMemory_ef31 {
  strings:
    $key_ef31 = { b8 43 [2] 8a 61 [2] 8c 54 [2] a2 54 [2] 9d 48 }

  condition:
    any of them
}