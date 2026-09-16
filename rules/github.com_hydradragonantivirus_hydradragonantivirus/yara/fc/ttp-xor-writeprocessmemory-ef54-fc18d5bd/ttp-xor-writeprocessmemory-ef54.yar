rule TTP_XOR_WriteProcessMemory_ef54 {
  strings:
    $key_ef54 = { b8 26 [2] 8a 04 [2] 8c 31 [2] a2 31 [2] 9d 2d }

  condition:
    any of them
}